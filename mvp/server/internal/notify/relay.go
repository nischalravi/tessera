package notify

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The tenant's own SMTP relay (Admin > Notifications and Email delivery, schema/0760_tenant_mail_relay.sql). When it is
// enabled, the tenant's notification email goes through it instead of the server's relay (TESSERA_SMTP_*). The password is
// sealed under the KEK and never shown again; the host is refused if it is, or resolves to, an internal address, here and
// again at connection time by the guarded dialer (internal/safehttp), the same SSRF rule every outbound call follows.

// RelayEnv is what the relay checks and the sender need from the running server.
type RelayEnv struct {
	Env           string // config.Dev or config.Prod
	AllowLoopback bool   // the dev loopback exception (a local relay such as MailHog)
	Sealer        *seal.Sealer
	// Resolver looks the host up; nil: the system resolver.
	Resolver safehttp.Resolver
}

func (e RelayEnv) dev() bool { return e.Env != config.Prod && e.AllowLoopback }

// RelaySpec is what an administrator saves.
type RelaySpec struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	TLS     string `json:"tls"`
	// Username and Password are the relay's login. Password is write-only: empty keeps the stored one, ClearPassword
	// removes it.
	Username      string `json:"username"`
	Password      string `json:"password"`
	ClearPassword bool   `json:"clear_password"`
	From          string `json:"from"`
}

// RelayPasswordAAD binds a tenant's sealed relay password to the tenant, table and column.
func RelayPasswordAAD(t tenancy.ID) []byte {
	return seal.AAD(t, "tenant_mail_relay", "password_sealed")
}

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$`)

// internalSuffixes are names that never reach a public relay.
var internalSuffixes = []string{".local", ".localhost", ".internal", ".localdomain", ".lan", ".home", ".corp", ".intranet", ".home.arpa", ".svc", ".cluster.local"}

// CheckRelayHost refuses a relay host that is, or resolves to, an internal address.
func (e RelayEnv) CheckRelayHost(ctx context.Context, host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	bad := func(code, msg string) error { return cfgerr.Refuse(422, code, "%s", msg) }
	if host == "" || len(host) > 253 {
		return bad("invalid_host", "the relay host is a DNS name or a public IP address")
	}
	allowLoop := func(a netip.Addr) bool { return e.dev() && a.Unmap().IsLoopback() }
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" || safehttp.Blocked(a) && !allowLoop(a) {
			return bad("internal_host", "the relay host is an internal address: Tessera sends only to public relays")
		}
		return nil
	}
	if !hostRE.MatchString(host) {
		return bad("invalid_host", "the relay host is a DNS name or a public IP address")
	}
	if host == "localhost" && e.dev() {
		return nil
	}
	if host == "localhost" || !strings.Contains(host, ".") {
		return bad("internal_host", "the relay host must be a fully qualified public name")
	}
	for _, s := range internalSuffixes {
		if strings.HasSuffix(host, s) {
			return bad("internal_host", "the relay host looks like an internal name: Tessera sends only to public relays")
		}
	}
	res := e.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := res.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return bad("host_unresolved", "the relay host does not resolve")
	}
	for _, a := range addrs {
		if safehttp.Blocked(a) && !allowLoop(a) {
			return bad("internal_host", "the relay host resolves to an internal address: Tessera sends only to public relays")
		}
	}
	return nil
}

// Check validates a spec's fields (not the host's address; see CheckRelayHost).
func (s *RelaySpec) Check(env RelayEnv, hasPassword bool) error {
	s.Host, s.Username, s.From = strings.ToLower(strings.TrimSpace(s.Host)), strings.TrimSpace(s.Username), strings.TrimSpace(s.From)
	refuse := func(code, msg string) error { return cfgerr.Refuse(422, code, "%s", msg) }
	switch {
	case s.Port < 1 || s.Port > 65535:
		return refuse("invalid_port", "the port is 1 to 65535")
	case s.TLS != config.SMTPStartTLS && s.TLS != config.SMTPTLS && s.TLS != config.SMTPNoTLS:
		return refuse("invalid_tls", "tls is starttls, tls or none")
	case s.TLS == config.SMTPNoTLS && env.Env == config.Prod:
		return refuse("tls_required", "a relay without TLS is not allowed in production")
	case len(s.Username) > 256 || strings.IndexFunc(s.Username, unicode.IsControl) >= 0:
		return refuse("invalid_username", "the username is up to 256 characters, without control characters")
	case len(s.Password) > 512 || strings.ContainsAny(s.Password, "\r\n\x00"):
		return refuse("invalid_password", "the password is up to 512 characters, without line breaks")
	case s.Password != "" && s.ClearPassword:
		return refuse("invalid_password", "send a password or clear_password, not both")
	case s.Username != "" && s.Password == "" && (!hasPassword || s.ClearPassword):
		return refuse("password_required", "a relay login needs a password")
	case s.Username == "" && s.Password != "":
		return refuse("username_required", "a password needs a username")
	}
	if _, err := mail.ParseAddress(s.From); err != nil || len(s.From) > 320 || strings.ContainsAny(s.From, "\r\n") {
		return refuse("invalid_from", "from is an email address, for example \"Tessera <tessera@example.com>\"")
	}
	return nil
}

// RelayState is a tenant's relay as the API shows it: everything but the password.
type RelayState struct {
	Configured     bool       `json:"configured"`
	Enabled        bool       `json:"enabled"`
	Host           string     `json:"host"`
	Port           int        `json:"port"`
	TLS            string     `json:"tls"`
	Username       string     `json:"username"`
	HasPassword    bool       `json:"has_password"`
	From           string     `json:"from"`
	LastTestAt     *time.Time `json:"last_test_at"`
	LastTestResult string     `json:"last_test_result"`
	Version        int        `json:"version"`
	UpdatedBy      string     `json:"updated_by,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

// LoadRelay returns the tenant's relay state; the zero state (Version 0) when none is saved.
func LoadRelay(tx *store.TenantTx) (RelayState, error) {
	r, err := tx.MailRelay()
	if errors.Is(err, store.ErrNotFound) {
		return RelayState{Port: 587, TLS: config.SMTPStartTLS}, nil
	} else if err != nil {
		return RelayState{}, err
	}
	at := r.UpdatedAt
	return RelayState{Configured: true, Enabled: r.Enabled, Host: r.Host, Port: r.Port, TLS: r.TLS, Username: r.Username,
		HasPassword: len(r.PasswordSealed) > 0, From: r.From, LastTestAt: r.LastTestAt, LastTestResult: r.LastTestResult,
		Version: r.Version, UpdatedBy: r.UpdatedBy, UpdatedAt: &at}, nil
}

// SaveRelay validates and replaces the tenant's relay. ver is the version the caller read (0: none saved); a different
// current version is a conflict. The password is sealed here; the audit event carries the host and port, never a
// credential.
func SaveRelay(ctx context.Context, tx *store.TenantTx, env RelayEnv, s RelaySpec, ver int, by string, now time.Time) error {
	old, err := tx.MailRelay()
	have := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	cur := 0
	if have {
		cur = old.Version
	}
	if ver != cur {
		return cfgerr.Conflict(ver, cur)
	}
	if err := s.Check(env, have && len(old.PasswordSealed) > 0); err != nil {
		return err
	}
	if err := env.CheckRelayHost(ctx, s.Host); err != nil {
		return err
	}
	row := &store.MailRelayRow{Enabled: s.Enabled, Host: s.Host, Port: s.Port, TLS: s.TLS, Username: s.Username, From: s.From, UpdatedBy: by}
	switch {
	case s.Password != "":
		if env.Sealer == nil {
			return errors.New("notify: no key to seal the relay password with")
		}
		if row.PasswordSealed, err = env.Sealer.Seal([]byte(s.Password), RelayPasswordAAD(tx.Tenant())); err != nil {
			return err
		}
	case have && !s.ClearPassword && s.Username != "":
		row.PasswordSealed = old.PasswordSealed
	}
	if err := tx.PutMailRelay(row, now); err != nil {
		return err
	}
	return tx.Audit(now, by, "mail.relay.update", ojson.Object{{Key: "enabled", Value: s.Enabled}, {Key: "host", Value: s.Host},
		{Key: "port", Value: s.Port}, {Key: "tls", Value: s.TLS}, {Key: "username_set", Value: s.Username != ""},
		{Key: "password", Value: passwordChange(s, have && len(old.PasswordSealed) > 0)}, {Key: "from", Value: s.From}, {Key: "version", Value: cur + 1}})
}

func passwordChange(s RelaySpec, had bool) string {
	switch {
	case s.Password != "":
		return "replaced"
	case s.ClearPassword || s.Username == "":
		return "none"
	case had:
		return "kept"
	}
	return "none"
}

// DeleteRelay removes the tenant's relay: the server's relay sends again.
func DeleteRelay(tx *store.TenantTx, ver int, by string, now time.Time) error {
	r, err := tx.MailRelay()
	if errors.Is(err, store.ErrNotFound) {
		return &Error{http.StatusNotFound, "relay_not_found", "the tenant has no relay of its own"}
	} else if err != nil {
		return err
	}
	if ver != r.Version {
		return cfgerr.Conflict(ver, r.Version)
	}
	if err := tx.DeleteMailRelay(); err != nil {
		return err
	}
	return tx.Audit(now, by, "mail.relay.delete", ojson.Object{{Key: "host", Value: r.Host}, {Key: "port", Value: r.Port}})
}

// Sender builds the SMTP sender of a stored relay: the password opened, every connection through the guarded dialer.
func (e RelayEnv) Sender(t tenancy.ID, r *store.MailRelayRow) (*SMTP, error) {
	pw := ""
	if len(r.PasswordSealed) > 0 {
		if e.Sealer == nil {
			return nil, errors.New("the tenant relay's password cannot be opened: no key")
		}
		b, err := e.Sealer.Open(r.PasswordSealed, RelayPasswordAAD(t))
		if err != nil {
			return nil, errors.New("the tenant relay's password cannot be opened (wrong KEK)")
		}
		pw = string(b)
	}
	env := e.Env
	if env != config.Prod {
		env = config.Dev
	}
	dial, err := safehttp.NewDialer(safehttp.Options{Env: env, AllowLoopback: e.AllowLoopback && env == config.Dev, AllowedPorts: []int{r.Port}, Resolver: e.Resolver})
	if err != nil {
		return nil, err
	}
	return &SMTP{Host: r.Host, Port: r.Port, Username: r.Username, password: pw, From: r.From, TLS: r.TLS, Timeout: 30 * time.Second, Dial: dial}, nil
}

// TestRelay sends one test message to `to` through the tenant's saved relay (enabled or not) and records the outcome. The
// result carries the relay's answers, never a credential.
func TestRelay(ctx context.Context, tx *store.TenantTx, env RelayEnv, to, by string, now time.Time) (*Attempt, error) {
	r, err := tx.MailRelay()
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Error{http.StatusNotFound, "relay_not_found", "save a relay first"}
	} else if err != nil {
		return nil, err
	}
	snd, err := env.Sender(tx.Tenant(), r)
	if err != nil {
		return nil, &Error{http.StatusConflict, "relay_unusable", err.Error()}
	}
	if err := env.CheckRelayHost(ctx, r.Host); err != nil {
		return nil, err
	}
	id := uuid.NewString()
	att, _ := snd.SendRecorded(ctx, Email{ID: id, To: to, Subject: "Tessera test message",
		Body: "This message tests the SMTP relay you saved in Tessera. Nothing else is needed: you can delete it."})
	result := att.Outcome
	if att.Error != "" {
		result += ": " + att.Error
	}
	if len(result) > 300 {
		result = result[:300]
	}
	if err := tx.SetMailRelayTest(now, result); err != nil {
		return nil, err
	}
	d := ojson.Object{{Key: "host", Value: r.Host}, {Key: "port", Value: r.Port}, {Key: "outcome", Value: att.Outcome}}
	if att.QueueID != "" {
		d = append(d, ojson.KV{Key: "queue_id", Value: att.QueueID})
	}
	return att, tx.Audit(now, by, "mail.relay.test", d)
}
