// Package config loads Tessera's typed settings from the environment and
// enforces the production guard rails (design
// docs/design/phase-0-platform-security.md §18.1 and §18.4).
//
// Load never has side effects: it reads variables (and the KEK file, when one
// is named) and returns either a valid *Config or every problem it found,
// joined. With TESSERA_ENV=prod it refuses to start when any of these hold:
// the public URL is not https; COOKIE_SECURE is false; there is no KEK;
// CORS_ORIGINS is not empty (the UI is same-origin in production, so CORS is
// off, §11); OUTBOUND_ALLOW_LOOPBACK is true; TESSERA_SAFEDIAL_ALLOW is set; TESSERA_DEV_IDP_URL is set; the
// audit anchor is not an s3:// URL (missing or file:// included); TESSERA_NOW freezes the clock; a
// trusted-proxy prefix is shorter than /8 (IPv4) or /32 (IPv6). The guard rail on dev_mock IdP connections
// needs the idp_connections table and lands with it (PR6).
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Environments. Test is a non-production environment like Dev (the shared
// Test instance and go test): it exposes dev sign-in (§18.4) and is the only
// environment the test-only session helper (internal/auth/authtest) runs in.
const (
	Dev  = "dev"
	Test = "test"
	Prod = "prod"
)

// Upper bounds enforced in every environment (§18.1).
const (
	MaxAccessTokenTTLSeconds = 900
	MaxDeviceCodeTTLSeconds  = 600
)

// Shortest trusted-proxy prefixes accepted with TESSERA_ENV=prod. A broader
// prefix (0.0.0.0/0 above all) would let any client spoof X-Forwarded-For.
const (
	MinProxyPrefixIPv4 = 8
	MinProxyPrefixIPv6 = 32
)

// Config is the typed configuration. The KEK is held behind a pointer so
// printing a Config (even with %#v) never shows key bytes; String and
// LogValue redact it as well.
type Config struct {
	Env                   string // Dev or Prod
	PublicURL             string // issuer base; https in prod
	APIAudience           string // access-token aud
	DB                    string // SQLite path (or sqlite:///path), or a postgres:// DSN (carries a password: never log it)
	KEKFile               string // TESSERA_KEK_FILE, when set
	CookieSecure          bool
	CORSOrigins           []string
	TrustedProxies        []netip.Prefix
	OutboundAllowLoopback bool // safehttp may reach 127.0.0.1 / ::1 (dev only)
	// SafedialAllow is TESSERA_SAFEDIAL_ALLOW: comma-separated host:port or
	// CIDR:port entries a dev instance may dial on private addresses (live
	// LDAP checks against a lab directory). Dev only; syntax is checked by
	// safedial.ParseAllow. Production reaches private directories through the
	// Directory Agent instead.
	SafedialAllow          string
	AuditAnchor            string
	AuditCheckpointSeconds int
	AuditCheckpointEvents  int
	// AuthRateBurst and AnonRateBurst are the per-IP burst sizes of the
	// /api/auth/* and anonymous request limiters (TESSERA_AUTH_RATE_BURST,
	// TESSERA_ANON_RATE_BURST; defaults 30 and 120). Browser test suites from
	// one address raise them.
	AuthRateBurst         int
	AnonRateBurst         int
	AccessTokenTTLSeconds int
	DeviceCodeTTLSeconds  int
	DPoPRSNonce           bool
	RPID                  string
	Notify                string
	DevIdPURL             string
	// FakeTarget is TESSERA_DEV_FAKE_TARGET: cmd/tessera starts an in-process
	// fake SCIM target on a loopback port, so the provisioning screens can be
	// demonstrated without a real system. Refused in prod.
	FakeTarget bool
	// Mail is the notification email delivery (issue #189).
	Mail Mail
	// NotifyMaxAttempts is how many times the dispatcher tries to send one
	// email before it is a dead letter (TESSERA_NOTIFY_MAX_ATTEMPTS).
	NotifyMaxAttempts int
	// NotifyDigestHour is the UTC hour from which the daily digest is built
	// (TESSERA_NOTIFY_DIGEST_HOUR).
	NotifyDigestHour int
	// FrozenNow is TESSERA_NOW (tests and demos; refused in prod). The zero
	// time means the wall clock; use Clock.
	FrozenNow time.Time

	kek *secretKey // decoded TESSERA_KEK or TESSERA_KEK_FILE; nil means "dev auto-generated"
	// outbound is the validated environment and loopback exception, set
	// only by Load. safehttp.ForConfig reads it (Outbound), so neither a
	// hand-built Config nor one whose exported fields were edited after
	// Load can turn the loopback exception on.
	outbound *outboundSettings
}

type outboundSettings struct {
	env           string
	allowLoopback bool
}

// Outbound returns the environment and loopback exception validated by
// Load; ok is false for a Config that Load did not return.
func (c *Config) Outbound() (env string, allowLoopback, ok bool) {
	if c == nil || c.outbound == nil {
		return "", false, false
	}
	return c.outbound.env, c.outbound.allowLoopback, true
}

type secretKey struct{ b []byte }

// Mail modes (TESSERA_NOTIFY_EMAIL).
const (
	MailOff  = "off"  // no email is sent; deliveries are recorded as skipped
	MailDev  = "dev"  // the dev sink: messages are logged and appended to var/dev-mail.jsonl
	MailSMTP = "smtp" // an SMTP relay (TESSERA_SMTP_*)
)

// SMTP TLS modes (TESSERA_SMTP_TLS).
const (
	SMTPStartTLS = "starttls" // upgrade a plain connection (port 587)
	SMTPTLS      = "tls"      // TLS from the first byte (port 465)
	SMTPNoTLS    = "none"     // plain text; dev only
)

// Mail configures the email sender. The SMTP password is never held in
// clear: PasswordSealed is the base64 of seal.Seal(password,
// seal.AAD(tenancy.Platform, "smtp", "password")) under the KEK; produce it
// with `tessera notify seal-password`.
type Mail struct {
	Mode           string // MailOff, MailDev or MailSMTP
	Host           string
	Port           int
	Username       string
	PasswordSealed string // base64; empty for a relay that needs no login
	From           string // an RFC 5322 address
	TLS            string // SMTPStartTLS, SMTPTLS or SMTPNoTLS
}

// String describes the mail settings without the sealed password.
func (m Mail) String() string {
	return fmt.Sprintf("mail{mode=%s host=%s port=%d tls=%s from=%s}", m.Mode, m.Host, m.Port, m.TLS, m.From)
}

// Load reads the configuration through getenv (os.Getenv in production,
// a map in tests) and validates it, including the production guard rails.
func Load(getenv func(string) string) (*Config, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	c := &Config{Env: getenv("TESSERA_ENV")}
	switch c.Env {
	case "":
		c.Env = Dev // design default; serve still requires an explicit TESSERA_ENV=dev
	case Dev, Test, Prod:
	default:
		return nil, fmt.Errorf("config: invalid TESSERA_ENV %q: want TESSERA_ENV=dev, test or prod", c.Env)
	}
	prod := c.Env == Prod
	def := func(devValue, prodValue string) string {
		if prod {
			return prodValue
		}
		return devValue
	}
	str := func(k, devValue, prodValue string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def(devValue, prodValue)
	}
	boolean := func(k string, devValue, prodValue bool) bool {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			if prod {
				return prodValue
			}
			return devValue
		}
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
		bad("%s: %q is not a boolean", k, v)
		return false
	}
	integer := func(k string, d, lo, hi int) int {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			return d
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			bad("%s: %q must be an integer from %d to %d", k, v, lo, hi)
			return d
		}
		return n
	}

	c.PublicURL = strings.TrimRight(str("TESSERA_PUBLIC_URL", "http://localhost:5173", ""), "/")
	c.APIAudience = str("TESSERA_API_AUDIENCE", c.PublicURL+"/api", c.PublicURL+"/api")
	c.DB = dbPath(getenv("TESSERA_DB"))
	c.CookieSecure = boolean("TESSERA_COOKIE_SECURE", true, true)
	c.CORSOrigins = corsOrigins(getenv("TESSERA_CORS_ORIGINS"), getenv("UI_PORT"), prod)
	c.OutboundAllowLoopback = boolean("TESSERA_OUTBOUND_ALLOW_LOOPBACK", true, false)
	// dev default: var/audit-anchors.jsonl next to the database (AnchorURL)
	c.SafedialAllow = strings.TrimSpace(getenv("TESSERA_SAFEDIAL_ALLOW"))
	c.AuditAnchor = str("TESSERA_AUDIT_ANCHOR", "", "")
	if a := c.AuditAnchor; a != "" && !strings.HasPrefix(a, "file://") && !strings.HasPrefix(a, "s3://") {
		bad("TESSERA_AUDIT_ANCHOR: %q is not a file:// or s3:// URL", a)
	}
	c.AuditCheckpointSeconds = integer("TESSERA_AUDIT_CHECKPOINT_SECONDS", 300, 1, 86400)
	c.AuditCheckpointEvents = integer("TESSERA_AUDIT_CHECKPOINT_EVENTS", 1000, 1, 1_000_000)
	c.AuthRateBurst = integer("TESSERA_AUTH_RATE_BURST", 30, 1, 100_000)
	c.AnonRateBurst = integer("TESSERA_ANON_RATE_BURST", 120, 1, 100_000)
	c.AccessTokenTTLSeconds = integer("TESSERA_AT_TTL_SECONDS", 600, 1, MaxAccessTokenTTLSeconds)
	c.DeviceCodeTTLSeconds = integer("TESSERA_DEVICE_CODE_TTL_SECONDS", 300, 1, MaxDeviceCodeTTLSeconds)
	c.DPoPRSNonce = boolean("TESSERA_DPOP_RS_NONCE", false, false)
	c.Notify = str("TESSERA_NOTIFY", "log", "log")
	c.NotifyMaxAttempts = integer("TESSERA_NOTIFY_MAX_ATTEMPTS", 6, 1, 20)
	c.NotifyDigestHour = integer("TESSERA_NOTIFY_DIGEST_HOUR", 8, 0, 23)
	c.Mail = loadMail(getenv, prod, integer, bad)
	if v := strings.TrimSpace(getenv("TESSERA_NOW")); v != "" {
		t, err := timeutil.ParseISO(v)
		switch {
		case err != nil:
			bad("TESSERA_NOW: %v", err)
		case t.IsZero():
			bad("TESSERA_NOW: %q is not a usable time", v)
		default:
			c.FrozenNow = t
		}
	}
	c.FakeTarget = boolean("TESSERA_DEV_FAKE_TARGET", false, false)
	c.DevIdPURL = strings.TrimSpace(getenv("TESSERA_DEV_IDP_URL"))
	if c.DevIdPURL == "" && !prod {
		c.DevIdPURL = "http://127.0.0.1:8001"
	}

	pub, err := parsePublicURL(c.PublicURL)
	switch {
	case c.PublicURL == "":
		bad("TESSERA_PUBLIC_URL is required with TESSERA_ENV=prod (an https URL)")
	case err != nil:
		bad("TESSERA_PUBLIC_URL: %v", err)
	case prod && pub.Scheme != "https":
		bad("TESSERA_PUBLIC_URL must be https with TESSERA_ENV=prod (got %s)", pub.Scheme)
	case prod && DevOnlyURL(c.PublicURL) != "":
		bad("TESSERA_PUBLIC_URL must not be %s with TESSERA_ENV=prod", DevOnlyURL(c.PublicURL))
	}
	// §11: the insecure-cookie fallback (Safari on http://localhost) only in
	// dev, and only for a localhost public URL.
	if !c.CookieSecure && !prod {
		if c.Env != Dev || pub == nil || (pub.Hostname() != "localhost" && pub.Hostname() != "127.0.0.1") {
			bad("TESSERA_COOKIE_SECURE=false is allowed only with TESSERA_ENV=dev and a localhost TESSERA_PUBLIC_URL")
		}
	}
	c.RPID = str("TESSERA_RP_ID", "localhost", "")
	if c.RPID == "" && pub != nil {
		c.RPID = pub.Hostname()
	}

	var perr error
	if c.TrustedProxies, perr = parseProxies(str("TESSERA_TRUSTED_PROXIES", "127.0.0.1", "")); perr != nil {
		bad("TESSERA_TRUSTED_PROXIES: %v", perr)
	}

	// KEK: TESSERA_KEK (base64 of 32 bytes) or TESSERA_KEK_FILE (a file
	// holding that base64), never both.
	inline, file := strings.TrimSpace(getenv("TESSERA_KEK")), strings.TrimSpace(getenv("TESSERA_KEK_FILE"))
	switch {
	case inline != "" && file != "":
		bad("set only one of TESSERA_KEK and TESSERA_KEK_FILE")
	case inline != "":
		k, err := decodeKEK(inline)
		if err != nil {
			bad("TESSERA_KEK: %v", err)
		} else {
			c.kek = &secretKey{k}
		}
	case file != "":
		c.KEKFile = file
		k, err := readKEKFile(file)
		if err != nil {
			bad("TESSERA_KEK_FILE: %v", err)
		} else {
			c.kek = &secretKey{k}
		}
	case prod:
		bad("a KEK is required with TESSERA_ENV=prod (set TESSERA_KEK_FILE or TESSERA_KEK)")
	}

	if prod {
		if !c.CookieSecure {
			bad("TESSERA_COOKIE_SECURE must be true with TESSERA_ENV=prod")
		}
		if len(c.CORSOrigins) > 0 {
			// §11/§18.1: the production UI is same-origin, so CORS is off.
			// The CSRF Origin check already admits the PUBLIC_URL origin.
			bad("TESSERA_CORS_ORIGINS must be empty with TESSERA_ENV=prod: the UI is same-origin and CORS is off (got %q)",
				strings.Join(c.CORSOrigins, ","))
		}
		if !c.FrozenNow.IsZero() {
			bad("TESSERA_NOW must not be set with TESSERA_ENV=prod (it freezes the clock and stops key rotation)")
		}
		for _, p := range c.TrustedProxies {
			if want := minProxyBits(p); p.Bits() < want {
				bad("TESSERA_TRUSTED_PROXIES: %s is broader than /%d with TESSERA_ENV=prod; list the load balancer CIDRs", p, want)
			}
		}
		if c.OutboundAllowLoopback {
			bad("TESSERA_OUTBOUND_ALLOW_LOOPBACK must be false with TESSERA_ENV=prod")
		}
		if c.DevIdPURL != "" {
			bad("TESSERA_DEV_IDP_URL must not be set with TESSERA_ENV=prod")
		}
		if c.FakeTarget {
			bad("TESSERA_DEV_FAKE_TARGET must not be set with TESSERA_ENV=prod (the fake provisioning target accepts any change)")
		}
		if IsPostgresDSN(c.DB) {
			// Never echo the DSN: it carries the password.
			if msg := checkProdPostgres(c.DB); msg != "" {
				bad("TESSERA_DB: %s", msg)
			}
		}
		if c.SafedialAllow != "" {
			bad("TESSERA_SAFEDIAL_ALLOW must not be set with TESSERA_ENV=prod: private directories are reached through the Directory Agent")
		}
		// s3:// is the only off-host sink so far; a file:// anchor sits on
		// the same host as the ledger it is meant to anchor.
		switch {
		case c.AuditAnchor == "":
			bad("TESSERA_AUDIT_ANCHOR is required with TESSERA_ENV=prod (s3://…)")
		case strings.HasPrefix(strings.ToLower(c.AuditAnchor), "file:"):
			bad("TESSERA_AUDIT_ANCHOR must not be file:// with TESSERA_ENV=prod (use s3://…)")
		case !strings.HasPrefix(c.AuditAnchor, "s3://") || len(c.AuditAnchor) == len("s3://"):
			bad("TESSERA_AUDIT_ANCHOR must be an s3://bucket/prefix URL with TESSERA_ENV=prod (got %q)", c.AuditAnchor)
		}
	}
	if len(errs) > 0 {
		if prod {
			return nil, fmt.Errorf("config: refusing to start with TESSERA_ENV=prod: %w", errors.Join(errs...))
		}
		return nil, fmt.Errorf("config: %w", errors.Join(errs...))
	}
	c.outbound = &outboundSettings{env: c.Env, allowLoopback: c.OutboundAllowLoopback}
	return c, nil
}

// loadMail reads TESSERA_NOTIFY_EMAIL and TESSERA_SMTP_*: smtp when a host is
// set, else the dev sink outside production and off in production. Production
// refuses the dev sink and SMTP without TLS.
func loadMail(getenv func(string) string, prod bool, integer func(string, int, int, int) int, bad func(string, ...any)) Mail {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	m := Mail{Host: get("TESSERA_SMTP_HOST"), Username: get("TESSERA_SMTP_USERNAME"),
		PasswordSealed: get("TESSERA_SMTP_PASSWORD_SEALED"), From: get("TESSERA_SMTP_FROM"), TLS: get("TESSERA_SMTP_TLS")}
	m.Port = integer("TESSERA_SMTP_PORT", 587, 1, 65535)
	switch m.Mode = strings.ToLower(get("TESSERA_NOTIFY_EMAIL")); m.Mode {
	case "":
		switch {
		case m.Host != "":
			m.Mode = MailSMTP
		case prod:
			m.Mode = MailOff
		default:
			m.Mode = MailDev
		}
	case MailOff, MailDev, MailSMTP:
	default:
		bad("TESSERA_NOTIFY_EMAIL: %q is not off, dev or smtp", m.Mode)
		m.Mode = MailOff
	}
	if m.TLS == "" {
		m.TLS = SMTPStartTLS
	}
	switch m.TLS {
	case SMTPStartTLS, SMTPTLS, SMTPNoTLS:
	default:
		bad("TESSERA_SMTP_TLS: %q is not starttls, tls or none", m.TLS)
	}
	if prod && m.Mode == MailDev {
		bad("TESSERA_NOTIFY_EMAIL=dev (the dev sink) must not be used with TESSERA_ENV=prod: set TESSERA_SMTP_HOST, or TESSERA_NOTIFY_EMAIL=off")
	}
	if m.Mode == MailSMTP {
		switch {
		case m.Host == "":
			bad("TESSERA_SMTP_HOST is required with TESSERA_NOTIFY_EMAIL=smtp")
		case strings.ContainsAny(m.Host, "/@ \t\r\n"):
			bad("TESSERA_SMTP_HOST must be a host name or address")
		}
		if a, err := mail.ParseAddress(m.From); err != nil || a.Address == "" {
			bad("TESSERA_SMTP_FROM is required with smtp and must be an email address")
		}
		if prod && m.TLS == SMTPNoTLS {
			bad("TESSERA_SMTP_TLS=none must not be used with TESSERA_ENV=prod")
		}
		if m.Username != "" && m.PasswordSealed == "" {
			bad("TESSERA_SMTP_PASSWORD_SEALED is required with TESSERA_SMTP_USERNAME (seal it with `tessera notify seal-password`; the password is never read in clear)")
		}
		if m.PasswordSealed != "" {
			if _, err := base64.StdEncoding.DecodeString(m.PasswordSealed); err != nil {
				bad("TESSERA_SMTP_PASSWORD_SEALED: not valid base64")
			}
		}
	}
	return m
}

// Clock is the clock to run on: TESSERA_NOW when set (dev only), otherwise
// the wall clock.
func (c *Config) Clock() timeutil.Clock {
	if c.FrozenNow.IsZero() {
		return timeutil.System
	}
	return timeutil.Frozen(c.FrozenNow)
}

// IsProd reports whether the production guard rails apply.
func (c *Config) IsProd() bool { return c.Env == Prod }

// PublicOrigin is the origin (scheme://host[:port]) of PublicURL, which the
// CSRF Origin check always admits.
func (c *Config) PublicOrigin() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// String describes the configuration without the KEK.
func (c *Config) String() string {
	return fmt.Sprintf("config{env=%s public_url=%s kek=%s cors=%v outbound_allow_loopback=%t}",
		c.Env, c.PublicURL, c.kekSource(), c.CORSOrigins, c.OutboundAllowLoopback)
}

// LogValue renders the configuration for slog without the KEK.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(slog.String("env", c.Env), slog.String("public_url", c.PublicURL),
		slog.String("kek", c.kekSource()), slog.Any("cors_origins", c.CORSOrigins),
		slog.Bool("outbound_allow_loopback", c.OutboundAllowLoopback))
}

func (c *Config) kekSource() string {
	switch {
	case c.KEKFile != "":
		return "file:" + c.KEKFile + " (REDACTED)"
	case c.kek != nil:
		return "env (REDACTED)"
	}
	return "dev auto-generated"
}

// AnchorURL is the audit anchor sink: TESSERA_AUDIT_ANCHOR, or in dev the
// file var/audit-anchors.jsonl next to the database (server/var for the
// default database). Load refuses a missing or file:// anchor in prod.
func (c *Config) AnchorURL(dbPath string) string {
	if c.AuditAnchor != "" || c.IsProd() {
		return c.AuditAnchor
	}
	return DevAnchorURL(dbPath)
}

// DevAnchorURL is the dev anchor file for a database path.
func DevAnchorURL(dbPath string) string {
	p, err := filepath.Abs(filepath.Join(localDir(dbPath), "var", "audit-anchors.jsonl"))
	if err != nil {
		p = filepath.Join(localDir(dbPath), "var", "audit-anchors.jsonl")
	}
	return "file://" + filepath.ToSlash(p)
}

// DevKEKPath is where a dev KEK is generated: var/dev-kek next to the
// database file (server/var/dev-kek for the default database).
func DevKEKPath(dbPath string) string {
	return filepath.Join(localDir(dbPath), "var", "dev-kek")
}

// localDir is the directory dev files (KEK, anchors) live in: next to a
// SQLite database file, or the working directory for a Postgres DSN.
func localDir(dbPath string) string {
	if IsPostgresDSN(dbPath) {
		return "."
	}
	return filepath.Dir(dbPath)
}

// IsPostgresDSN reports whether a database setting is a postgres:// URL.
func IsPostgresDSN(s string) bool {
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

// checkProdPostgres returns what is wrong with a production Postgres DSN, or
// "". It requires TLS to the server and an app_role: the application must run
// as the non-owner role so row-level security binds it (design §14.3).
func checkProdPostgres(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "is not a valid postgres:// URL"
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "is not a valid postgres:// URL"
	}
	var problems []string
	switch q.Get("sslmode") {
	case "require", "verify-ca", "verify-full":
	default:
		problems = append(problems, "sslmode must be require, verify-ca or verify-full with TESSERA_ENV=prod")
	}
	if q.Get("app_role") == "" {
		problems = append(problems, "app_role (the NOSUPERUSER, NOBYPASSRLS role, usually tessera_app) is required with TESSERA_ENV=prod so row-level security applies")
	}
	return strings.Join(problems, "; ")
}

// DevMailPath is where the dev mail sink appends: var/dev-mail.jsonl next to
// the database file.
func DevMailPath(dbPath string) string {
	return filepath.Join(localDir(dbPath), "var", "dev-mail.jsonl")
}

// Sealer returns the KEK sealer. With no KEK configured (dev only; Load
// refuses that in prod) it loads the dev KEK at devKEKPath, generating it
// with mode 0600 on first use.
func (c *Config) Sealer(devKEKPath string) (*seal.Sealer, error) {
	if c.kek != nil {
		return seal.New(c.kek.b)
	}
	if c.IsProd() {
		return nil, errors.New("config: no KEK configured")
	}
	k, err := readKEKFile(devKEKPath)
	if errors.Is(err, fs.ErrNotExist) {
		k = seal.RandomBytes(seal.KeySize)
		switch err := writeDevKEK(devKEKPath, k); {
		case errors.Is(err, fs.ErrExist):
			// another process won the race: use its KEK (read once; no
			// retry loop, e.g. on a dangling symlink)
			if k, err = readKEKFile(devKEKPath); err != nil {
				return nil, fmt.Errorf("config: dev KEK %s: %w", devKEKPath, err)
			}
		case err != nil:
			return nil, fmt.Errorf("config: dev KEK: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("config: dev KEK %s: %w", devKEKPath, err)
	}
	return seal.New(k)
}

// writeDevKEK writes k to a mode-0600 temp file in path's directory, syncs
// it, and then links it into place, so path is either absent or holds a
// complete KEK (a crash mid-write leaves only a temp file, never a torn
// KEK). The link is atomic and, unlike rename, never replaces a KEK another
// process placed first (fs.ErrExist).
func writeDevKEK(path string, k []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".dev-kek-*.tmp") // mode 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(k) + "\n")
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- the KEK's own directory
		_ = d.Sync() // persist the new directory entry
		_ = d.Close()
	}
	return nil
}

func decodeKEK(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("not valid base64")
	}
	if len(k) != seal.KeySize {
		return nil, fmt.Errorf("must decode to %d bytes (got %d)", seal.KeySize, len(k))
	}
	return k, nil
}

// readKEKFile reads a base64 KEK file. It refuses a file that group or
// other users can access, or that is not a regular file.
func readKEKFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible to other users (mode %04o); chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-chosen KEK path
	if err != nil {
		return nil, err
	}
	return decodeKEK(string(b))
}

// DevOnlyURL says why a URL may be used only in development: plain http,
// or a host that is localhost or a loopback, private or link-local
// address. "" means the URL is fine in production. Load applies it to
// TESSERA_PUBLIC_URL, and the configuration import (internal/transport)
// to every URL in a bundle applied to a production server.
func DevOnlyURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme == "http" || u.Scheme == "ws" {
		return "plain " + u.Scheme
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "a localhost address"
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		switch {
		case a.IsLoopback():
			return "a loopback address"
		case a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsUnspecified():
			return "a private or link-local address"
		}
	}
	return ""
}

func parsePublicURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("not a URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("scheme must be https (got %q)", u.Scheme)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must be scheme://host[:port][/path] with no user info, query or fragment")
	}
	return u, nil
}

func parseProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			pf, err := netip.ParsePrefix(p)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP or CIDR", p)
			}
			if pf.Bits() == 0 { // every address would be a trusted proxy
				return nil, fmt.Errorf("%q trusts every address; list the proxy CIDRs", p)
			}
			out = append(out, pf.Masked())
			continue
		}
		a, err := netip.ParseAddr(p)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR", p)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// minProxyBits is the shortest prod prefix for p's address family. An
// IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/n) counts as IPv4 at n-96 bits, so
// ::ffff:0:0/96 is refused like 0.0.0.0/0.
func minProxyBits(p netip.Prefix) int {
	switch {
	case p.Addr().Is4():
		return MinProxyPrefixIPv4
	case p.Addr().Is4In6():
		return 96 + MinProxyPrefixIPv4
	}
	return MinProxyPrefixIPv6
}

// dbPath accepts a plain path or the Python backend's sqlite:/// URL form.
func dbPath(v string) string {
	if v == "" {
		return "tessera.db"
	}
	return strings.TrimPrefix(v, "sqlite:///")
}

// corsOrigins: an explicit comma-separated list wins; otherwise dev allows the
// dev UI on localhost and 127.0.0.1 (port UI_PORT or 5173) and prod allows
// none.
func corsOrigins(v, uiPort string, prod bool) []string {
	if v != "" {
		var out []string
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
				out = append(out, o)
			}
		}
		return out
	}
	if prod {
		return nil
	}
	if uiPort == "" {
		uiPort = "5173"
	}
	return []string{"http://localhost:" + uiPort, "http://127.0.0.1:" + uiPort}
}
