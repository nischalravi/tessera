package alerts

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// Message is one email.
type Message struct {
	To      []string
	Subject string
	Text    string
}

// Mailer sends email. TESSERA_NOTIFY picks it: "log" writes messages to the
// server log (the design default), smtp://user:pass@host:587?from=addr sends
// with STARTTLS required, smtps://… with implicit TLS (port 465).
//
// SMTP is not HTTP, so internal/safehttp does not apply; the SMTP host is
// operator configuration, never tenant input.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// NewMailer builds the mailer for a TESSERA_NOTIFY value.
func NewMailer(notify string, log *slog.Logger) (Mailer, error) {
	if notify == "" || notify == "log" {
		return LogMailer{Log: log}, nil
	}
	u, err := url.Parse(notify)
	if err != nil || (u.Scheme != "smtp" && u.Scheme != "smtps") || u.Hostname() == "" {
		return nil, fmt.Errorf("alerts: TESSERA_NOTIFY must be log, smtp://… or smtps://… (got %q)", redactURL(notify))
	}
	q, _ := url.ParseQuery(u.RawQuery)
	from := q.Get("from")
	if _, err := parseAddr(from); err != nil {
		return nil, errors.New("alerts: TESSERA_NOTIFY needs ?from=<address>")
	}
	m := &SMTPMailer{Host: u.Hostname(), Port: u.Port(), From: from, ImplicitTLS: u.Scheme == "smtps"}
	if m.Port == "" {
		m.Port = map[bool]string{true: "465", false: "587"}[m.ImplicitTLS]
	}
	if u.User != nil {
		m.Username = u.User.Username()
		m.Password, _ = u.User.Password()
	}
	return m, nil
}

func redactURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.User != nil {
		u.User = url.User("…")
		return u.String()
	}
	return s
}

// LogMailer writes each message to the log instead of sending it.
type LogMailer struct{ Log *slog.Logger }

// Send logs m.
func (l LogMailer) Send(_ context.Context, m Message) error {
	if l.Log != nil {
		l.Log.Info("alert email (TESSERA_NOTIFY=log)", "to", strings.Join(m.To, ", "), "subject", m.Subject)
	}
	return nil
}

// SMTPMailer sends through an SMTP relay.
type SMTPMailer struct {
	Host, Port         string
	From               string
	Username, Password string
	ImplicitTLS        bool
	// RootCAs replaces the system roots (tests).
	TLS *tls.Config
}

const smtpTimeout = 15 * time.Second

// Send delivers m. STARTTLS is required: a relay that does not offer it is refused.
func (s *SMTPMailer) Send(ctx context.Context, m Message) error {
	for _, to := range m.To {
		if _, err := parseAddr(to); err != nil {
			return fmt.Errorf("smtp: bad recipient %q", to)
		}
	}
	tcfg := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	if s.TLS != nil {
		tcfg = s.TLS.Clone()
		if tcfg.ServerName == "" {
			tcfg.ServerName = s.Host
		}
	}
	addr := net.JoinHostPort(s.Host, s.Port)
	d := &net.Dialer{Timeout: smtpTimeout}
	var conn net.Conn
	var err error
	if s.ImplicitTLS {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tcfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer c.Close()
	if !s.ImplicitTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: the relay does not offer STARTTLS")
		}
		if err := c.StartTLS(tcfg); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := c.Mail(s.From); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	for _, to := range m.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("smtp: rcpt: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if _, err := w.Write(buildMessage(s.From, m)); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return c.Quit()
}

func parseAddr(s string) (string, error) {
	a, err := mailParse(s)
	if err != nil {
		return "", err
	}
	return a, nil
}

// headerSafe drops CR and LF so a value cannot add headers.
func headerSafe(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func buildMessage(from string, m Message) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(from))
	fmt.Fprintf(&b, "To: %s\r\n", headerSafe(strings.Join(m.To, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", headerSafe(m.Subject))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	// net/smtp's data writer dot-stuffs lines
	for _, line := range strings.Split(strings.ReplaceAll(m.Text, "\r\n", "\n"), "\n") {
		b.WriteString(line + "\r\n")
	}
	return []byte(b.String())
}
