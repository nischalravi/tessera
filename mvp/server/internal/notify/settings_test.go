package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// stubResolver answers host lookups from a table, so a test needs no DNS.
type stubResolver map[string][]string

func (r stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ips, ok := r[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, s := range ips {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func code(err error) string {
	var ce *cfgerr.Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	var ne *notify.Error
	if errors.As(err, &ne) {
		return ne.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func relayEnv(env string, loopback bool) notify.RelayEnv {
	s, _ := seal.New([]byte("0123456789abcdef0123456789abcdef"))
	return notify.RelayEnv{Env: env, AllowLoopback: loopback, Sealer: s, Resolver: stubResolver{
		"smtp.example.com": {"93.184.216.34"}, "mail.internal-only.example.com": {"10.0.0.5"}, "meta.example.com": {"169.254.169.254"},
		"mixed.example.com": {"93.184.216.35", "192.168.1.9"}, "v6.example.com": {"2606:2800:220:1::1"}, "local.example.com": {"127.0.0.1"}}}
}

// The relay host is refused when it is, or resolves to, an internal address, in production and in development; the dev
// loopback exception admits a local relay only in development.
func TestCheckRelayHost(t *testing.T) {
	cases := []struct {
		name     string
		env      notify.RelayEnv
		host     string
		wantCode string
	}{
		{"public name", relayEnv("prod", false), "smtp.example.com", ""},
		{"public name, any case and a trailing dot", relayEnv("prod", false), "SMTP.Example.com.", ""},
		{"public address", relayEnv("prod", false), "93.184.216.36", ""},
		{"public IPv6 address", relayEnv("prod", false), "2606:2800:220:1::7", ""},
		{"private address", relayEnv("prod", false), "10.1.2.3", "internal_host"},
		{"private 192.168", relayEnv("prod", false), "192.168.0.1", "internal_host"},
		{"loopback", relayEnv("prod", false), "127.0.0.1", "internal_host"},
		{"metadata address", relayEnv("prod", false), "169.254.169.254", "internal_host"},
		{"IPv6 loopback", relayEnv("prod", false), "::1", "internal_host"},
		{"IPv4-mapped loopback", relayEnv("prod", false), "::ffff:127.0.0.1", "internal_host"},
		{"localhost", relayEnv("prod", false), "localhost", "internal_host"},
		{"a name with no dot", relayEnv("prod", false), "mailhost", "internal_host"},
		{"an internal suffix", relayEnv("prod", false), "smtp.corp", "internal_host"},
		{".internal", relayEnv("prod", false), "smtp.something.internal", "internal_host"},
		{"resolves to a private address", relayEnv("prod", false), "mail.internal-only.example.com", "internal_host"},
		{"resolves to the metadata address", relayEnv("prod", false), "meta.example.com", "internal_host"},
		{"one of several addresses is private", relayEnv("prod", false), "mixed.example.com", "internal_host"},
		{"does not resolve", relayEnv("prod", false), "nowhere.example.com", "host_unresolved"},
		{"not a host name", relayEnv("prod", false), "smtp example.com", "invalid_host"},
		{"user info is not a host", relayEnv("prod", false), "a@smtp.example.com", "invalid_host"},
		{"a URL is not a host", relayEnv("prod", false), "smtp.example.com/x", "invalid_host"},
		{"empty", relayEnv("prod", false), "", "invalid_host"},
		{"loopback in dev without the exception", relayEnv("dev", false), "127.0.0.1", "internal_host"},
		{"loopback in dev with the exception", relayEnv("dev", true), "127.0.0.1", ""},
		{"localhost in dev with the exception", relayEnv("dev", true), "localhost", ""},
		{"a name on loopback in dev with the exception", relayEnv("dev", true), "local.example.com", ""},
		{"private address in dev stays refused", relayEnv("dev", true), "10.1.2.3", "internal_host"},
		{"the exception is not honoured in prod", relayEnv("prod", true), "127.0.0.1", "internal_host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := code(tc.env.CheckRelayHost(context.Background(), tc.host)); got != tc.wantCode {
				t.Errorf("code = %q, want %q", got, tc.wantCode)
			}
		})
	}
}

func TestRelaySpecCheck(t *testing.T) {
	good := func() notify.RelaySpec {
		return notify.RelaySpec{Enabled: true, Host: "smtp.example.com", Port: 587, TLS: "starttls", Username: "u", Password: "p", From: "Tessera <tessera@example.com>"}
	}
	cases := []struct {
		name        string
		mod         func(*notify.RelaySpec)
		env         string
		hasPassword bool
		want        string
	}{
		{"good", func(*notify.RelaySpec) {}, "prod", false, ""},
		{"no login", func(s *notify.RelaySpec) { s.Username, s.Password = "", "" }, "prod", false, ""},
		{"keep the stored password", func(s *notify.RelaySpec) { s.Password = "" }, "prod", true, ""},
		{"port 0", func(s *notify.RelaySpec) { s.Port = 0 }, "prod", false, "invalid_port"},
		{"port too high", func(s *notify.RelaySpec) { s.Port = 70000 }, "prod", false, "invalid_port"},
		{"unknown tls", func(s *notify.RelaySpec) { s.TLS = "ssl" }, "prod", false, "invalid_tls"},
		{"no tls in prod", func(s *notify.RelaySpec) { s.TLS = "none" }, "prod", false, "tls_required"},
		{"no tls in dev", func(s *notify.RelaySpec) { s.TLS = "none" }, "dev", false, ""},
		{"login without a password", func(s *notify.RelaySpec) { s.Password = "" }, "prod", false, "password_required"},
		{"clearing the password of a login", func(s *notify.RelaySpec) { s.Password, s.ClearPassword = "", true }, "prod", true, "password_required"},
		{"password and clear", func(s *notify.RelaySpec) { s.ClearPassword = true }, "prod", true, "invalid_password"},
		{"password without a username", func(s *notify.RelaySpec) { s.Username = "" }, "prod", false, "username_required"},
		{"password with a line break", func(s *notify.RelaySpec) { s.Password = "a\r\nQUIT" }, "prod", false, "invalid_password"},
		{"control character in the username", func(s *notify.RelaySpec) { s.Username = "u\x00" }, "prod", false, "invalid_username"},
		{"from is not an address", func(s *notify.RelaySpec) { s.From = "not an address" }, "prod", false, "invalid_from"},
		{"from with a header injection", func(s *notify.RelaySpec) { s.From = "a@example.com\r\nBcc: x@y.example" }, "prod", false, "invalid_from"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := good()
			tc.mod(&s)
			if got := code(s.Check(relayEnv(tc.env, false), tc.hasPassword)); got != tc.want {
				t.Errorf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

// The relay password is sealed to the tenant, shown to no one, kept when a save leaves it empty and never put in the audit log.
func TestSaveRelaySealsThePassword(t *testing.T) {
	w := newWorld(t)
	env := relayEnv("prod", false)
	spec := notify.RelaySpec{Enabled: true, Host: "smtp.example.com", Port: 587, TLS: "starttls", Username: "tessera", Password: "s3cret-relay-password", From: "tessera@example.com"}
	w.tx(func(c *store.TenantTx) error {
		if err := notify.SaveRelay(context.Background(), c, env, spec, 0, "admin", w.now); err != nil {
			t.Fatal(err)
		}
		row, err := c.MailRelay()
		if err != nil || row.Version != 1 || len(row.PasswordSealed) == 0 || strings.Contains(string(row.PasswordSealed), "s3cret") {
			t.Fatalf("row = %+v, %v", row, err)
		}
		if b, err := env.Sealer.Open(row.PasswordSealed, notify.RelayPasswordAAD(c.Tenant())); err != nil || string(b) != "s3cret-relay-password" {
			t.Errorf("the tenant's own AAD opens it to %q, %v", b, err)
		}
		if _, err := env.Sealer.Open(row.PasswordSealed, notify.RelayPasswordAAD(w.f.A.ID)); err == nil {
			t.Error("another tenant's AAD opened the sealed password")
		}
		st, _ := notify.LoadRelay(c)
		if b, _ := json.Marshal(st); strings.Contains(string(b), "s3cret") || !st.HasPassword || st.Host != "smtp.example.com" {
			t.Errorf("state = %s", b)
		}
		// an empty password keeps the stored one; a stale version is a conflict
		spec.Password, spec.Port = "", 465
		if err := notify.SaveRelay(context.Background(), c, env, spec, 0, "admin", w.now); code(err) != "version_conflict" {
			t.Errorf("stale save = %v", err)
		}
		if err := notify.SaveRelay(context.Background(), c, env, spec, 1, "admin", w.now); err != nil {
			t.Fatal(err)
		}
		row2, _ := c.MailRelay()
		if row2.Version != 2 || row2.Port != 465 || string(row2.PasswordSealed) != string(row.PasswordSealed) {
			t.Errorf("after a save without a password: %+v", row2)
		}
		// an internal host is refused and changes nothing
		bad := spec
		bad.Host = "10.0.0.8"
		if err := notify.SaveRelay(context.Background(), c, env, bad, 2, "admin", w.now); code(err) != "internal_host" {
			t.Errorf("internal host = %v", err)
		}
		// clearing the login clears the password
		spec.Username, spec.ClearPassword = "", true
		if err := notify.SaveRelay(context.Background(), c, env, spec, 2, "admin", w.now); err != nil {
			t.Fatal(err)
		}
		if r3, _ := c.MailRelay(); len(r3.PasswordSealed) != 0 {
			t.Error("the password is still stored")
		}
		return nil
	})
	w.read(func(c *store.TenantTx) {
		log, err := c.AuditLog(-1)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range log {
			if strings.Contains(string(e.Detail), "s3cret") {
				t.Errorf("the password is in the audit log: %s", e.Detail)
			}
			if e.Action == "mail.relay.update" {
				n++
			}
		}
		if n != 3 {
			t.Errorf("%d mail.relay.update events, want 3", n)
		}
	})
}

// A tenant that has its own relay sends through it, and not through the server's.
func TestDispatchUsesTheTenantsRelay(t *testing.T) {
	w := newWorld(t)
	f := newFakeSMTP(t)
	env := relayEnv("dev", true)
	w.tx(func(c *store.TenantTx) error {
		return notify.SaveRelay(context.Background(), c, env, notify.RelaySpec{Enabled: true, Host: "127.0.0.1", Port: f.port(), TLS: "none",
			From: "Larkspur <noreply@larkspur.example>"}, 0, "admin", w.now)
	})
	w.emit(notify.KindApprovalNeeded, "k1", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	server := &notify.MemorySender{}
	d := w.dispatcher(server, &clock{t: w.now})
	d.Relay = env
	if st := w.run(d); st.Sent != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if server.Count() != 0 {
		t.Errorf("the server's relay sent %d emails", server.Count())
	}
	if !strings.Contains(f.from, "noreply@larkspur.example") || len(f.to) != 1 || !strings.Contains(f.to[0], w.annEmail) {
		t.Errorf("tenant relay envelope: from %q to %v", f.from, f.to)
	}
	// the delivery log shows the tenant relay's transcript
	w.read(func(c *store.TenantTx) {
		ms, _ := c.EmailMessages(store.EmailFilter{})
		if len(ms) != 1 || ms[0].Status != store.EmailAccepted || ms[0].QueueID == nil || *ms[0].QueueID != "ABC123" {
			t.Errorf("messages = %+v", ms)
		}
	})
	// email works with the tenant's relay even when the server has none
	w.emit(notify.KindApprovalNeeded, "k2", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	d2 := w.dispatcher(nil, &clock{t: w.now})
	d2.Relay = env
	if st := w.run(d2); st.Sent != 1 || st.Skipped != 0 {
		t.Errorf("without a server relay: %+v", st)
	}
	// switching it off sends through the server's relay again
	w.tx(func(c *store.TenantTx) error {
		return notify.SaveRelay(context.Background(), c, env, notify.RelaySpec{Enabled: false, Host: "127.0.0.1", Port: f.port(), TLS: "none",
			From: "Larkspur <noreply@larkspur.example>"}, 1, "admin", w.now)
	})
	w.emit(notify.KindApprovalNeeded, "k3", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	if st := w.run(d); st.Sent != 1 || server.Count() != 1 {
		t.Errorf("relay off: %+v, server sent %d", st, server.Count())
	}
}

// A tenant relay that cannot be built (a wrong key) fails visibly and is retried; it never falls back to the server's relay.
func TestDispatchTenantRelayThatCannotBeOpenedDoesNotFallBack(t *testing.T) {
	w := newWorld(t)
	env := relayEnv("dev", true)
	w.tx(func(c *store.TenantTx) error {
		return notify.SaveRelay(context.Background(), c, env, notify.RelaySpec{Enabled: true, Host: "127.0.0.1", Port: 2525, TLS: "none",
			Username: "u", Password: "p", From: "noreply@larkspur.example"}, 0, "admin", w.now)
	})
	w.emit(notify.KindApprovalNeeded, "k1", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	server := &notify.MemorySender{}
	d := w.dispatcher(server, &clock{t: w.now})
	other, _ := seal.New([]byte("ffffffffffffffffffffffffffffffff"))
	d.Relay = notify.RelayEnv{Env: "dev", AllowLoopback: true, Sealer: other}
	st := w.run(d)
	if st.Sent != 0 || st.Retried != 1 || server.Count() != 0 {
		t.Fatalf("stats = %+v, server sent %d", st, server.Count())
	}
	if n := w.one(w.ann); n.LastError == nil || !strings.Contains(*n.LastError, "cannot be opened") {
		t.Errorf("last error = %v", n.LastError)
	}
}

// A test message goes through the saved relay and records an outcome without a credential.
func TestTestRelay(t *testing.T) {
	w := newWorld(t)
	f := newFakeSMTP(t)
	env := relayEnv("dev", true)
	w.tx(func(c *store.TenantTx) error {
		if _, err := notify.TestRelay(context.Background(), c, env, "ann@b.example", "admin", w.now); code(err) != "relay_not_found" {
			t.Errorf("no relay: %v", err)
		}
		if err := notify.SaveRelay(context.Background(), c, env, notify.RelaySpec{Enabled: false, Host: "127.0.0.1", Port: f.port(), TLS: "none", From: "noreply@larkspur.example"}, 0, "admin", w.now); err != nil {
			t.Fatal(err)
		}
		att, err := notify.TestRelay(context.Background(), c, env, "ann@b.example", "admin", w.now)
		if err != nil || att.Outcome != notify.OutcomeAccepted {
			t.Fatalf("test = %+v, %v", att, err)
		}
		row, _ := c.MailRelay()
		if row.LastTestAt == nil || !strings.HasPrefix(row.LastTestResult, "accepted") {
			t.Errorf("last test = %v %q", row.LastTestAt, row.LastTestResult)
		}
		return nil
	})
	if !strings.Contains(f.data, "Subject: Tessera test message") || len(f.to) != 1 {
		t.Errorf("relay got %q to %v", f.data, f.to)
	}
	if w.audited("mail.relay.test") != 1 {
		t.Error("the test is not audited")
	}
}
