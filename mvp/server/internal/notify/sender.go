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
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
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
func (d *DevSink) Send(_ context.Context, e Email) error {
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

// SMTP sends through an SMTP relay with the standard library. Every
// connection goes through safehttp's guarded dialer, so a relay name that
// resolves to a private, loopback or metadata address is refused (SSRF),
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
	tlsConf  *tls.Config
}

// NewSMTP builds the sender from the mail configuration: it opens the sealed
// password with the KEK sealer and uses the guarded dialer for env.
func NewSMTP(m config.Mail, env string, allowLoopback bool, s *seal.Sealer) (*SMTP, error) {
	return newSMTP(m, env, allowLoopback, s, nil, nil)
}

func newSMTP(m config.Mail, env string, allowLoopback bool, s *seal.Sealer, resolver safehttp.Resolver, tlsConf *tls.Config) (*SMTP, error) {
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
	dial, err := safehttp.NewDialer(safehttp.Options{Env: env, AllowLoopback: allowLoopback && env == config.Dev, Resolver: resolver})
	if err != nil {
		return nil, err
	}
	if tlsConf == nil {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &SMTP{Host: m.Host, Port: m.Port, Username: m.Username, password: pw, From: m.From, TLS: m.TLS,
		Timeout: 30 * time.Second, Dial: dial, tlsConf: tlsConf}, nil
}

// String never shows the password.
func (c *SMTP) String() string { return fmt.Sprintf("smtp{%s:%d tls=%s}", c.Host, c.Port, c.TLS) }

// Send delivers one message.
func (c *SMTP) Send(ctx context.Context, e Email) error {
	if err := validAddress(e.To); err != nil {
		return err
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return fmt.Errorf("%w: invalid from address", ErrPermanent)
	}
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
	tc := c.tlsConf.Clone()
	tc.ServerName = c.Host
	if c.TLS == config.SMTPTLS {
		conn = tls.Client(conn, tc)
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	if c.TLS == config.SMTPStartTLS {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("notify: the SMTP relay does not offer STARTTLS")
		}
		if err := cl.StartTLS(tc); err != nil {
			return err
		}
	}
	if c.Username != "" {
		if c.TLS == config.SMTPNoTLS {
			return fmt.Errorf("%w: refusing to send a password without TLS", ErrPermanent)
		}
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.password, c.Host)); err != nil {
			return classify(err)
		}
	}
	if err := cl.Mail(from.Address); err != nil {
		return classify(err)
	}
	if err := cl.Rcpt(e.To); err != nil {
		return classify(err)
	}
	w, err := cl.Data()
	if err != nil {
		return classify(err)
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return classify(err)
	}
	return cl.Quit()
}

// classify makes a 5xx reply permanent and leaves 4xx and network errors to retry.
func classify(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 {
		return fmt.Errorf("%w: %v", ErrPermanent, err)
	}
	return err
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
