package notify_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
)

// fakeSMTP is a minimal SMTP server on loopback: it records the envelope and
// the message, and answers RCPT with rcpt (default 250).
type fakeSMTP struct {
	ln   net.Listener
	rcpt string
	mu   sync.Mutex
	from string
	to   []string
	data string
}

func newFakeSMTP(t *testing.T, rcpt string) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener:", err)
	}
	f := &fakeSMTP{ln: ln, rcpt: rcpt}
	if f.rcpt == "" {
		f.rcpt = "250 ok"
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(s string) { _, _ = w.WriteString(s + "\r\n"); _ = w.Flush() }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.mu.Lock()
			f.from = strings.TrimSpace(line[len("MAIL FROM:"):])
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			if strings.HasPrefix(f.rcpt, "250") {
				f.mu.Lock()
				f.to = append(f.to, strings.TrimSpace(line[len("RCPT TO:"):]))
				f.mu.Unlock()
			}
			say(f.rcpt)
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func testSealer(t *testing.T) *seal.Sealer {
	t.Helper()
	s, err := seal.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func smtpFor(t *testing.T, f *fakeSMTP, env string, loopback bool) *notify.SMTP {
	t.Helper()
	c, err := notify.NewSMTP(config.Mail{Mode: config.MailSMTP, Host: "127.0.0.1", Port: f.port(), From: "Tessera <tessera@example.com>",
		TLS: config.SMTPNoTLS}, env, loopback, testSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSMTP_SendsAMessage(t *testing.T) {
	f := newFakeSMTP(t, "")
	c := smtpFor(t, f, config.Dev, true)
	err := c.Send(context.Background(), notify.Email{ID: "n-1", To: "ann@b.example", Subject: "[Tessera] Approval needed\r\nBcc: evil@x.example",
		Body: "Hello.\nOpen in Tessera: https://t.example/inbox"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.from, "tessera@example.com") || len(f.to) != 1 || !strings.Contains(f.to[0], "ann@b.example") {
		t.Errorf("envelope from %q to %v", f.from, f.to)
	}
	head, body, _ := strings.Cut(f.data, "\r\n\r\n")
	for _, want := range []string{"To: ann@b.example", "Message-ID: <n-1@example.com>", "MIME-Version: 1.0", "Auto-Submitted: auto-generated"} {
		if !strings.Contains(head, want) {
			t.Errorf("header lacks %q:\n%s", want, head)
		}
	}
	if strings.Contains(head, "\r\nBcc:") {
		t.Errorf("a newline in the subject injected a header:\n%s", head)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(body), "\r\n", ""))
	if err != nil || !strings.Contains(string(raw), "Open in Tessera: https://t.example/inbox") {
		t.Errorf("body = %q, %v", raw, err)
	}
}

func TestSMTP_ClassifiesFailures(t *testing.T) {
	permanent := newFakeSMTP(t, "550 5.1.1 no such user")
	if err := smtpFor(t, permanent, config.Dev, true).Send(context.Background(), notify.Email{ID: "a", To: "x@b.example", Subject: "s", Body: "b"}); !errors.Is(err, notify.ErrPermanent) {
		t.Errorf("a 550 = %v, want ErrPermanent", err)
	}
	transient := newFakeSMTP(t, "451 4.3.0 try again later")
	if err := smtpFor(t, transient, config.Dev, true).Send(context.Background(), notify.Email{ID: "b", To: "x@b.example", Subject: "s", Body: "b"}); err == nil || errors.Is(err, notify.ErrPermanent) {
		t.Errorf("a 451 = %v, want a retryable error", err)
	}
	c := smtpFor(t, newFakeSMTP(t, ""), config.Dev, true)
	for _, to := range []string{"", "not an address", "a@b.example\r\nBcc: x@y.example", "Ann <a@b.example>", "a@b.example, c@d.example"} {
		if err := c.Send(context.Background(), notify.Email{ID: "c", To: to, Subject: "s", Body: "b"}); !errors.Is(err, notify.ErrPermanent) {
			t.Errorf("recipient %q = %v, want ErrPermanent", to, err)
		}
	}
}

// TestSMTP_UsesTheSSRFGuard: the relay is dialled through safehttp's guard,
// so loopback (and private and metadata addresses) are refused unless the dev
// exception is on.
func TestSMTP_UsesTheSSRFGuard(t *testing.T) {
	f := newFakeSMTP(t, "")
	for _, tc := range []struct {
		name, env string
		loopback  bool
	}{{"prod", config.Prod, false}, {"dev without the exception", config.Dev, false}} {
		err := smtpFor(t, f, tc.env, tc.loopback).Send(context.Background(), notify.Email{ID: "d", To: "x@b.example", Subject: "s", Body: "b"})
		if !errors.Is(err, safehttp.ErrBlockedAddress) {
			t.Errorf("%s: %v, want ErrBlockedAddress", tc.name, err)
		}
	}
	for _, host := range []string{"10.0.0.5", "169.254.169.254", "192.168.1.1", "[::1]"} {
		c, err := notify.NewSMTP(config.Mail{Mode: config.MailSMTP, Host: strings.Trim(host, "[]"), Port: 25, From: "t@example.com", TLS: config.SMTPNoTLS},
			config.Prod, false, testSealer(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Send(context.Background(), notify.Email{ID: "e", To: "x@b.example", Subject: "s", Body: "b"}); !errors.Is(err, safehttp.ErrBlockedAddress) {
			t.Errorf("relay %s: %v, want ErrBlockedAddress", host, err)
		}
	}
	if _, err := notify.NewSMTP(config.Mail{Mode: config.MailSMTP, Host: "h", Port: 25, From: "t@example.com"}, config.Prod, true, testSealer(t)); err != nil {
		t.Errorf("prod with loopback requested must quietly not allow it, got %v", err)
	}
}

func TestSMTP_PasswordIsSealed(t *testing.T) {
	s := testSealer(t)
	sealed, err := notify.SealPassword(s, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "hunter2") {
		t.Fatal("the sealed value holds the password")
	}
	m := config.Mail{Mode: config.MailSMTP, Host: "127.0.0.1", Port: 25, From: "t@example.com", Username: "u", PasswordSealed: sealed, TLS: config.SMTPStartTLS}
	c, err := notify.NewSMTP(m, config.Dev, true, s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.String(), "hunter2") || strings.Contains(c.String(), sealed) {
		t.Errorf("String shows secrets: %s", c)
	}
	other, _ := seal.New([]byte("fedcba9876543210fedcba9876543210"))
	if _, err := notify.NewSMTP(m, config.Dev, true, other); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("another KEK opened the password: %v", err)
	}
	m.PasswordSealed = "%%%"
	if _, err := notify.NewSMTP(m, config.Dev, true, s); err == nil {
		t.Error("garbage sealed password accepted")
	}
	if _, err := notify.SealPassword(s, ""); err == nil {
		t.Error("an empty password was sealed")
	}
}

// TestSMTP_NeverSendsAPasswordWithoutTLS.
func TestSMTP_NeverSendsAPasswordWithoutTLS(t *testing.T) {
	s := testSealer(t)
	sealed, _ := notify.SealPassword(s, "pw")
	f := newFakeSMTP(t, "")
	c, err := notify.NewSMTP(config.Mail{Mode: config.MailSMTP, Host: "127.0.0.1", Port: f.port(), From: "t@example.com", Username: "u",
		PasswordSealed: sealed, TLS: config.SMTPNoTLS}, config.Dev, true, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), notify.Email{ID: "f", To: "x@b.example", Subject: "s", Body: "b"}); !errors.Is(err, notify.ErrPermanent) {
		t.Errorf("auth without TLS = %v", err)
	}
}

func TestDevSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "var", "dev-mail.jsonl")
	d := &notify.DevSink{Path: path}
	if err := d.Send(context.Background(), notify.Email{ID: "1", To: "ann@b.example", Subject: "[Tessera] hi", Body: "body"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Send(context.Background(), notify.Email{ID: "2", To: "bad\naddress", Subject: "s", Body: "b"}); !errors.Is(err, notify.ErrPermanent) {
		t.Errorf("bad recipient = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var line map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &line); err != nil || line["to"] != "ann@b.example" || line["subject"] != "[Tessera] hi" || line["body"] != "body" {
		t.Errorf("sink line = %s, %v", raw, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("the sink file is accessible to others: %v", fi.Mode())
	}
}

func TestNewSender(t *testing.T) {
	s := testSealer(t)
	if sd, err := notify.NewSender(config.Mail{Mode: config.MailOff}, config.Dev, true, s, "", nil); sd != nil || err != nil {
		t.Errorf("off = %v, %v", sd, err)
	}
	if _, err := notify.NewSender(config.Mail{Mode: config.MailDev}, config.Prod, false, s, "", nil); err == nil {
		t.Error("the dev sink was built for prod")
	}
	if sd, err := notify.NewSender(config.Mail{Mode: config.MailDev}, config.Dev, true, s, "", nil); err != nil || sd == nil {
		t.Errorf("dev = %v, %v", sd, err)
	}
	if sd, err := notify.NewSender(config.Mail{Mode: config.MailSMTP, Host: "smtp.example.com", Port: 587, From: "t@example.com", TLS: config.SMTPStartTLS}, config.Prod, false, s, "", nil); err != nil || sd == nil {
		t.Errorf("smtp = %v, %v", sd, err)
	}
}
