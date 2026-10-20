package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// SendError is a failed delivery. Permanent errors (the destination
// rejected the batch itself) are dead-lettered after MaxAttempts; the rest
// retry until they succeed.
type SendError struct {
	Permanent bool
	Msg       string
}

func (e *SendError) Error() string { return e.Msg }

func retryable(format string, a ...any) error { return &SendError{Msg: fmt.Sprintf(format, a...)} }

// Sender delivers a batch, in order. Nil means the destination accepted it.
type Sender interface {
	Send(ctx context.Context, batch []Record) error
}

// ------------------------------------------------------------------ webhook

// Webhook flavors.
const (
	FlavorHEC  = "hec"  // Splunk HTTP Event Collector: newline-separated envelopes, "Authorization: Splunk <token>"
	FlavorJSON = "json" // a JSON array of events, "Authorization: Bearer <token>" (Sentinel, Cribl, Logstash, …)
)

// Webhook posts batches to an HTTPS endpoint. Client must come from
// internal/safehttp.
type Webhook struct {
	Client *http.Client
	URL    string
	Flavor string
	Token  string
	Host   string // HEC "host": the tenant slug
	Format string
}

// Body renders a batch as the request body.
func (w *Webhook) Body(batch []Record) []byte {
	var b bytes.Buffer
	if w.Flavor == FlavorHEC {
		sourcetype := "tessera:audit"
		if w.Format == FormatOCSF {
			sourcetype = "tessera:ocsf"
		}
		for _, r := range batch {
			ms := r.OccurredAt.UnixMilli()
			fmt.Fprintf(&b, `{"time":%d.%03d,"host":%s,"source":"tessera","sourcetype":%q,"event":`, ms/1000, ms%1000,
				strconv.Quote(w.Host), sourcetype)
			b.Write(r.Payload)
			b.WriteString("}\n")
		}
		return b.Bytes()
	}
	b.WriteByte('[')
	for i, r := range batch {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(r.Payload)
	}
	b.WriteByte(']')
	return b.Bytes()
}

// Send posts the batch.
func (w *Webhook) Send(ctx context.Context, batch []Record) error {
	if w.Client == nil {
		return retryable("webhook delivery is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(w.Body(batch)))
	if err != nil {
		return &SendError{Permanent: true, Msg: "bad webhook URL"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Tessera-SIEM/1")
	if w.Token != "" {
		scheme := "Bearer "
		if w.Flavor == FlavorHEC {
			scheme = "Splunk "
		}
		req.Header.Set("Authorization", scheme+w.Token)
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return retryable("webhook: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return retryable("webhook: HTTP %d", resp.StatusCode)
	default:
		return &SendError{Permanent: true, Msg: fmt.Sprintf("webhook: HTTP %d", resp.StatusCode)}
	}
}

// ------------------------------------------------------------------- syslog

// DefaultSyslogPort is the IANA port of syslog over TLS (RFC 5425).
const DefaultSyslogPort = "6514"

// syslogFacility is "log audit" (13).
const syslogFacility = 13

// Syslog sends RFC 5424 messages over TLS with RFC 5425 octet-counting
// framing. The collector's addresses are checked with the same rules as
// internal/safehttp before the dial, and the dial goes to the checked
// address, so DNS rebinding cannot reach a private one.
type Syslog struct {
	Addr      string // host:port
	RootCAs   *x509.CertPool
	Hostname  string // HOSTNAME field: the tenant slug
	Loopback  bool   // dev only: allow 127.0.0.1 / ::1
	Resolver  func(ctx context.Context, host string) ([]netip.Addr, error)
	Timeout   time.Duration
	tlsConfig *tls.Config // tests
}

// PRI severity of an outcome.
func syslogSeverity(outcome string) int {
	switch outcome {
	case "failure", "denied":
		return 4 // warning
	case "error":
		return 3 // error
	}
	return 6 // informational
}

func sdEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(s)
}

// msgID keeps printable US-ASCII and at most 32 characters (RFC 5424).
func msgID(action string) string {
	var b strings.Builder
	for _, c := range action {
		if c > 32 && c < 127 && b.Len() < 32 {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// Frame renders one record as an RFC 5425 frame.
func (s *Syslog) Frame(r Record) []byte {
	host := msgID(s.Hostname)
	msg := fmt.Sprintf("<%d>1 %s %s tessera - %s [tessera@32473 seq=\"%d\" hash=\"%s\"] ", syslogFacility*8+syslogSeverity(r.Outcome),
		r.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000Z"), host, msgID(r.Action), r.Seq, sdEscape(r.Hash))
	full := append([]byte(msg), r.Payload...)
	return append([]byte(strconv.Itoa(len(full))+" "), full...)
}

// resolverFunc adapts Syslog.Resolver to safehttp.Resolver.
type resolverFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	return f(ctx, host)
}

// dialer is the SSRF-guarded dialer of internal/safehttp (the one the SMTP
// sender uses): the host is resolved once, refused if any address is
// blocked, and only the checked addresses are connected to. Only the
// collector's own port is allowed.
func (s *Syslog) dialer(port int, timeout time.Duration) (safehttp.DialFunc, error) {
	env := config.Prod
	if s.Loopback {
		env = config.Dev
	}
	o := safehttp.Options{Env: env, AllowLoopback: s.Loopback, AllowedPorts: []int{port}, Timeout: timeout}
	if s.Resolver != nil {
		o.Resolver = resolverFunc(s.Resolver)
	}
	return safehttp.NewDialer(o)
}

// Send writes the batch on one TLS connection.
func (s *Syslog) Send(ctx context.Context, batch []Record) error {
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return &SendError{Permanent: true, Msg: "syslog: target must be host:port"}
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return &SendError{Permanent: true, Msg: "syslog: target must be host:port"}
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dial, err := s.dialer(portNum, timeout)
	if err != nil {
		return &SendError{Permanent: true, Msg: fmt.Sprintf("syslog: %v", err)}
	}
	raw, err := dial(ctx, "tcp", s.Addr)
	if err != nil {
		if errors.Is(err, safehttp.ErrBlockedAddress) || errors.Is(err, safehttp.ErrPort) {
			return &SendError{Permanent: true, Msg: fmt.Sprintf("syslog: %s resolves to a blocked address or port", host)}
		}
		return retryable("syslog: %v", err)
	}
	cfg := &tls.Config{ServerName: host, RootCAs: s.RootCAs, MinVersion: tls.VersionTLS12}
	if s.tlsConfig != nil {
		cfg = s.tlsConfig
	}
	conn := tls.Client(raw, cfg)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		return retryable("syslog: %v", err)
	}
	var buf bytes.Buffer
	for _, r := range batch {
		buf.Write(s.Frame(r))
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return retryable("syslog: %v", err)
	}
	return nil
}

// ParseCAs parses a PEM CA bundle.
func ParseCAs(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return nil, errors.New("no PEM certificates found")
	}
	return pool, nil
}
