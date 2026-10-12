package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Email is one message to send. ID is the notification id: it becomes the
// Message-ID, so a resend after a crash is recognisable as a duplicate.
type Email struct {
	ID      string
	To      string
	Subject string
	Body    string
}

// Sender delivers an email. Implementations return ErrPermanent (wrapped) for
// a failure that retrying cannot fix.
type Sender interface {
	Send(ctx context.Context, e Email) error
}

// ErrPermanent marks a send that will never succeed (a refused recipient, an
// invalid address): the notification becomes a dead letter at once.
var ErrPermanent = errors.New("notify: permanent send failure")

// validAddress accepts one plain address: no display name, no header
// injection.
func validAddress(a string) error {
	if a == "" || strings.ContainsAny(a, "\r\n") {
		return fmt.Errorf("%w: invalid recipient", ErrPermanent)
	}
	p, err := mail.ParseAddress(a)
	if err != nil || p.Address != a {
		return fmt.Errorf("%w: invalid recipient", ErrPermanent)
	}
	return nil
}

// ---------------------------------------------------------------- dev sink

// DevSink is the dev and test email sender: it sends nothing, logs each
// message (address and subject only) and appends it, body included, to a
// JSON-lines file when Path is set. config refuses it in production.
type DevSink struct {
	Path string
	Log  *slog.Logger
	mu   sync.Mutex
}

// Send records the message.
func (d *DevSink) Send(ctx context.Context, e Email) error {
	_, err := d.SendRecorded(ctx, e)
	return err
}

// SendRecorded records the message and returns a one-step transcript.
func (d *DevSink) SendRecorded(_ context.Context, e Email) (*Attempt, error) {
	a := &Attempt{Started: time.Now().UTC(), Banner: "dev mail sink (nothing is sent)", Steps: []Step{}, RcptTo: e.To}
	err := d.write(e)
	a.Finished = time.Now().UTC()
	switch {
	case err == nil:
		a.Outcome, a.QueueID = OutcomeAccepted, "dev-"+e.ID
		a.step("(dev sink)", 250, "2.0.0 recorded in the dev mail sink, not sent")
	case errors.Is(err, ErrPermanent):
		a.Outcome, a.Error = OutcomeRejected, "invalid recipient"
	default:
		a.Outcome, a.Error = OutcomeFailed, clipField(err.Error())
	}
	return a, err
}

func (d *DevSink) write(e Email) error {
	if err := validAddress(e.To); err != nil {
		return err
	}
	if d.Log != nil {
		d.Log.Info("dev mail sink: email not sent", "to", e.To, "subject", e.Subject, "id", e.ID)
	}
	if d.Path == "" {
		return nil
	}
	line, err := json.Marshal(map[string]string{"at": time.Now().UTC().Format(time.RFC3339), "id": e.ID, "to": e.To,
		"subject": e.Subject, "body": e.Body})
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(d.Path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(d.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- operator-chosen dev path
	if err != nil {
		return err
	}
	_, werr := f.Write(append(line, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// ---------------------------------------------------------------- SMTP

// passwordAAD binds a sealed SMTP password to its purpose.
func passwordAAD() []byte { return seal.AAD(tenancy.Platform, "smtp", "password") }

// SealPassword seals an SMTP password for TESSERA_SMTP_PASSWORD_SEALED
// (base64). `tessera notify seal-password` calls it.
func SealPassword(s *seal.Sealer, password string) (string, error) {
	if password == "" {
		return "", errors.New("notify: empty password")
	}
	b, err := s.Seal([]byte(password), passwordAAD())
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// SMTP sends through an SMTP relay with its own small client on the standard
// library (net/textproto), so it can record the transcript of each attempt.
// Every connection goes through safehttp's guarded dialer, so a relay name
// that resolves to a private, loopback or metadata address is refused (SSRF),
// except the dev loopback exception.
type SMTP struct {
	Host     string
	Port     int
	Username string
	password string
	From     string
	TLS      string
	Timeout  time.Duration
	Dial     safehttp.DialFunc
	// TLSConfig replaces the default (TLS 1.2 or later, system roots): a
	// private CA, or a test relay.
	TLSConfig *tls.Config
}

// NewSMTP builds the sender from the mail configuration: it opens the sealed
// password with the KEK sealer and uses the guarded dialer for env.
func NewSMTP(m config.Mail, env string, allowLoopback bool, s *seal.Sealer) (*SMTP, error) {
	pw := ""
	if m.PasswordSealed != "" {
		raw, err := base64.StdEncoding.DecodeString(m.PasswordSealed)
		if err != nil {
			return nil, errors.New("notify: the sealed SMTP password is not base64")
		}
		b, err := s.Open(raw, passwordAAD())
		if err != nil {
			return nil, errors.New("notify: cannot open the sealed SMTP password (wrong KEK, or not sealed with `tessera notify seal-password`)")
		}
		pw = string(b)
	}
	if env != config.Prod {
		env = config.Dev
	}
	dial, err := safehttp.NewDialer(safehttp.Options{Env: env, AllowLoopback: allowLoopback && env == config.Dev})
	if err != nil {
		return nil, err
	}
	return &SMTP{Host: m.Host, Port: m.Port, Username: m.Username, password: pw, From: m.From, TLS: m.TLS,
		Timeout: 30 * time.Second, Dial: dial}, nil
}

// String never shows the password.
func (c *SMTP) String() string { return fmt.Sprintf("smtp{%s:%d tls=%s}", c.Host, c.Port, c.TLS) }

// Send delivers one message.
func (c *SMTP) Send(ctx context.Context, e Email) error {
	_, err := c.SendRecorded(ctx, e)
	return err
}

// replyError is a relay reply that ended the attempt.
type replyError struct {
	Code int
	Msg  string
}

func (e *replyError) Error() string { return fmt.Sprintf("smtp %d: %s", e.Code, e.Msg) }

// SendRecorded delivers one message and returns the transcript of the attempt
// (also on failure). Outcome: accepted on 250 at the end of DATA, deferred on
// a 4xx, rejected on a 5xx or an address that can never work (the error then
// wraps ErrPermanent), failed on a network, TLS or timeout error.
func (c *SMTP) SendRecorded(ctx context.Context, e Email) (*Attempt, error) {
	a := &Attempt{Started: time.Now().UTC(), Steps: []Step{}}
	err := c.send(ctx, e, a)
	a.Finished = time.Now().UTC()
	var re *replyError
	switch {
	case err == nil:
		a.Outcome = OutcomeAccepted
	case errors.Is(err, ErrPermanent):
		a.Outcome = OutcomeRejected
	case errors.As(err, &re) && re.Code >= 500:
		a.Outcome, err = OutcomeRejected, fmt.Errorf("%w: %v", ErrPermanent, err)
	case errors.As(err, &re):
		a.Outcome = OutcomeDeferred
	default:
		a.Outcome = OutcomeFailed
	}
	if err != nil {
		a.Error = clipField(strings.ReplaceAll(err.Error(), e.To, "<recipient>"))
	}
	return a, err
}

func (c *SMTP) send(ctx context.Context, e Email, a *Attempt) error {
	if err := validAddress(e.To); err != nil {
		return err
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return fmt.Errorf("%w: invalid from address", ErrPermanent)
	}
	a.MailFrom, a.RcptTo = from.Address, e.To
	msg := buildMessage(from, e)
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	conn, err := c.Dial(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLSConfig != nil {
		tc = c.TLSConfig.Clone()
	}
	tc.ServerName = c.Host
	upgrade := func() error {
		tconn := tls.Client(conn, tc)
		if err := tconn.HandshakeContext(ctx); err != nil {
			a.TLS = &TLSInfo{Error: clipField(err.Error())}
			return fmt.Errorf("tls handshake: %w", err)
		}
		a.TLS = tlsInfo(tconn.ConnectionState())
		conn = tconn
		return nil
	}
	if c.TLS == config.SMTPTLS {
		if err := upgrade(); err != nil {
			return err
		}
	}
	text := textproto.NewConn(conn)
	// read takes one reply and records it; a reply of another class ends the attempt
	read := func(shown string, class int) (string, error) {
		code, msg, err := text.ReadResponse(0)
		if err != nil {
			return "", err
		}
		a.step(shown, code, msg)
		if code/100 != class {
			return msg, &replyError{code, clipField(msg)}
		}
		return msg, nil
	}
	cmd := func(line, shown string, class int) (string, error) {
		if err := text.PrintfLine("%s", line); err != nil {
			return "", err
		}
		return read(shown, class)
	}
	banner, err := read("(connect)", 2)
	if err != nil {
		return err
	}
	a.Banner = clipField(banner)
	hello := "tessera.invalid"
	if i := strings.LastIndex(from.Address, "@"); i >= 0 {
		hello = from.Address[i+1:]
	}
	ehlo := func() error {
		msg, err := cmd("EHLO "+hello, "EHLO "+hello, 2)
		if err != nil {
			return err
		}
		a.Capabilities = []string{}
		for _, l := range strings.Split(msg, "\n")[1:] {
			a.Capabilities = append(a.Capabilities, clipField(strings.TrimSpace(l)))
		}
		return nil
	}
	if err := ehlo(); err != nil {
		return err
	}
	if c.TLS == config.SMTPStartTLS {
		if !slices.ContainsFunc(a.Capabilities, func(s string) bool { return strings.EqualFold(s, "STARTTLS") }) {
			a.TLS = &TLSInfo{Error: "the relay does not offer STARTTLS"}
			return errors.New("notify: the SMTP relay does not offer STARTTLS")
		}
		if _, err := cmd("STARTTLS", "STARTTLS", 2); err != nil {
			a.TLS = &TLSInfo{Error: clipField(err.Error())}
			return fmt.Errorf("starttls refused: %s", err) // the connection could not be secured: a failure, retried
		}
		if err := upgrade(); err != nil {
			return err
		}
		text = textproto.NewConn(conn)
		if err := ehlo(); err != nil {
			return err
		}
	}
	if c.Username != "" {
		if c.TLS == config.SMTPNoTLS {
			return fmt.Errorf("%w: refusing to send a password without TLS", ErrPermanent)
		}
		token := base64.StdEncoding.EncodeToString([]byte("\x00" + c.Username + "\x00" + c.password))
		if _, err := cmd("AUTH PLAIN "+token, "AUTH PLAIN <redacted>", 2); err != nil {
			return err
		}
	}
	if _, err := cmd("MAIL FROM:<"+from.Address+">", "MAIL FROM:<"+from.Address+">", 2); err != nil {
		return err
	}
	if _, err := cmd("RCPT TO:<"+e.To+">", "RCPT TO:<"+e.To+">", 2); err != nil {
		return err
	}
	if _, err := cmd("DATA", "DATA", 3); err != nil {
		return err
	}
	w := text.DotWriter()
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	final, err := read("<message body not recorded>", 2)
	if err != nil {
		return err
	}
	a.QueueID = ParseQueueID(final)
	if text.PrintfLine("QUIT") == nil {
		if code, msg, err := text.ReadResponse(0); err == nil {
			a.step("QUIT", code, msg)
		}
	}
	return nil
}

// buildMessage renders a plain-text RFC 5322 message with CRLF line endings.
func buildMessage(from *mail.Address, e Email) []byte {
	host := "tessera.invalid"
	if i := strings.LastIndex(from.Address, "@"); i >= 0 {
		host = from.Address[i+1:]
	}
	clean := func(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }
	var b strings.Builder
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from.String())
	h("To", e.To)
	h("Subject", mime.QEncoding.Encode("utf-8", clean(e.Subject)))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+clean(e.ID)+"@"+host+">")
	h("MIME-Version", "1.0")
	h("Content-Type", `text/plain; charset="utf-8"`)
	h("Content-Transfer-Encoding", "base64")
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(e.Body, "\r\n", "\n")))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return []byte(b.String())
}

// ---------------------------------------------------------------- test sender

// MemorySender collects emails in memory, and fails as scripted. For tests.
type MemorySender struct {
	mu   sync.Mutex
	Sent []Email
	// Errs are returned by successive Send calls (nil: success); once used
	// up, sends succeed.
	Errs []error
}

// Send records the email, or returns the next scripted error.
func (m *MemorySender) Send(_ context.Context, e Email) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Errs) > 0 {
		err := m.Errs[0]
		m.Errs = m.Errs[1:]
		if err != nil {
			return err
		}
	}
	m.Sent = append(m.Sent, e)
	return nil
}

// Count returns how many emails were sent.
func (m *MemorySender) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Sent)
}

// NewSender returns the sender for the mail configuration: the dev sink, the
// SMTP relay, or nil (email off). devSinkPath is where the dev sink appends.
func NewSender(m config.Mail, env string, allowLoopback bool, s *seal.Sealer, devSinkPath string, log *slog.Logger) (Sender, error) {
	switch m.Mode {
	case config.MailDev:
		if env == config.Prod {
			return nil, errors.New("notify: the dev mail sink is not allowed with TESSERA_ENV=prod")
		}
		return &DevSink{Path: devSinkPath, Log: log}, nil
	case config.MailSMTP:
		return NewSMTP(m, env, allowLoopback, s)
	}
	return nil, nil
}
