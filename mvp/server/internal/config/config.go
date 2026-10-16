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
// audit anchor is missing or file://; TESSERA_NOW freezes the clock; a
// trusted-proxy prefix is shorter than /8 (IPv4) or /32 (IPv6). The guard rail on dev_mock IdP connections
// needs the idp_connections table and lands with it (PR6).
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
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
	DB                    string // SQLite path (or sqlite:///path)
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
	SafedialAllow string
	// AgentAddr is TESSERA_AGENT_ADDR: the address of the mutual-TLS listener
	// the Directory Agents connect to (DR-11). Empty: no listener, and
	// enrolled agents cannot connect. AgentTLSCert and AgentTLSKey
	// (TESSERA_AGENT_TLS_CERT, TESSERA_AGENT_TLS_KEY) are that listener's
	// certificate and key files, required whenever AgentAddr is set; the CA
	// that signs the certificate is the one the agents pin.
	AgentAddr              string
	AgentTLSCert           string
	AgentTLSKey            string
	AuditAnchor            string
	AuditCheckpointSeconds int
	AuditCheckpointEvents  int
	AccessTokenTTLSeconds  int
	DeviceCodeTTLSeconds   int
	DPoPRSNonce            bool
	RPID                   string
	Notify                 string
	DevIdPURL              string
	// FrozenNow is TESSERA_NOW (tests and demos; refused in prod). The zero
	// time means the wall clock; use Clock.
	FrozenNow time.Time

	kek *secretKey // decoded TESSERA_KEK or TESSERA_KEK_FILE; nil means "dev auto-generated"
}

type secretKey struct{ b []byte }

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
	c.AgentAddr = strings.TrimSpace(getenv("TESSERA_AGENT_ADDR"))
	c.AgentTLSCert = strings.TrimSpace(getenv("TESSERA_AGENT_TLS_CERT"))
	c.AgentTLSKey = strings.TrimSpace(getenv("TESSERA_AGENT_TLS_KEY"))
	if c.AgentAddr != "" && (c.AgentTLSCert == "" || c.AgentTLSKey == "") {
		bad("TESSERA_AGENT_ADDR needs TESSERA_AGENT_TLS_CERT and TESSERA_AGENT_TLS_KEY: the agent channel is mutual TLS only")
	}
	if c.AgentAddr == "" && (c.AgentTLSCert != "" || c.AgentTLSKey != "") {
		bad("TESSERA_AGENT_TLS_CERT and TESSERA_AGENT_TLS_KEY are set without TESSERA_AGENT_ADDR")
	}
	c.AuditAnchor = str("TESSERA_AUDIT_ANCHOR", "", "")
	if a := c.AuditAnchor; a != "" && !strings.HasPrefix(a, "file://") && !strings.HasPrefix(a, "s3://") {
		bad("TESSERA_AUDIT_ANCHOR: %q is not a file:// or s3:// URL", a)
	}
	c.AuditCheckpointSeconds = integer("TESSERA_AUDIT_CHECKPOINT_SECONDS", 300, 1, 86400)
	c.AuditCheckpointEvents = integer("TESSERA_AUDIT_CHECKPOINT_EVENTS", 1000, 1, 1_000_000)
	c.AccessTokenTTLSeconds = integer("TESSERA_AT_TTL_SECONDS", 600, 1, MaxAccessTokenTTLSeconds)
	c.DeviceCodeTTLSeconds = integer("TESSERA_DEVICE_CODE_TTL_SECONDS", 300, 1, MaxDeviceCodeTTLSeconds)
	c.DPoPRSNonce = boolean("TESSERA_DPOP_RS_NONCE", false, false)
	c.Notify = str("TESSERA_NOTIFY", "log", "log")
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
		if c.SafedialAllow != "" {
			bad("TESSERA_SAFEDIAL_ALLOW must not be set with TESSERA_ENV=prod: private directories are reached through the Directory Agent")
		}
		switch {
		case c.AuditAnchor == "":
			bad("TESSERA_AUDIT_ANCHOR is required with TESSERA_ENV=prod (s3://…)")
		case strings.HasPrefix(strings.ToLower(c.AuditAnchor), "file:"):
			bad("TESSERA_AUDIT_ANCHOR must not be file:// with TESSERA_ENV=prod")
		}
	}
	if len(errs) > 0 {
		if prod {
			return nil, fmt.Errorf("config: refusing to start with TESSERA_ENV=prod: %w", errors.Join(errs...))
		}
		return nil, fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return c, nil
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
	p, err := filepath.Abs(filepath.Join(filepath.Dir(dbPath), "var", "audit-anchors.jsonl"))
	if err != nil {
		p = filepath.Join(filepath.Dir(dbPath), "var", "audit-anchors.jsonl")
	}
	return "file://" + filepath.ToSlash(p)
}

// DevKEKPath is where a dev KEK is generated: var/dev-kek next to the
// database file (server/var/dev-kek for the default database).
func DevKEKPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "var", "dev-kek")
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
		if err := os.MkdirAll(filepath.Dir(devKEKPath), 0o700); err != nil {
			return nil, fmt.Errorf("config: dev KEK: %w", err)
		}
		enc := base64.StdEncoding.EncodeToString(k) + "\n"
		// O_EXCL: never overwrite a KEK another process just created.
		f, err := os.OpenFile(devKEKPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-chosen path
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return c.Sealer(devKEKPath)
			}
			return nil, fmt.Errorf("config: dev KEK: %w", err)
		}
		_, werr := f.WriteString(enc)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, fmt.Errorf("config: dev KEK: %w", werr)
		}
	} else if err != nil {
		return nil, fmt.Errorf("config: dev KEK %s: %w", devKEKPath, err)
	}
	return seal.New(k)
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
