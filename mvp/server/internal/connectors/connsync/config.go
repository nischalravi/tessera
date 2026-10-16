package connsync

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Runtime is what a connector needs from the process configuration: the
// environment and whether the dev loopback exception is on.
type Runtime struct {
	Env           string // config.Dev or config.Prod
	AllowLoopback bool
}

// RuntimeFromEnv reads TESSERA_ENV and TESSERA_OUTBOUND_ALLOW_LOOPBACK the way
// internal/config does (config.Load has already refused loopback in prod).
// Anything but "prod" is treated as dev-like for safehttp, which only knows dev
// and prod; "test" has the dev rules.
func RuntimeFromEnv(getenv func(string) string) Runtime {
	r := Runtime{Env: config.Dev}
	if getenv("TESSERA_ENV") == config.Prod {
		r.Env = config.Prod
		return r
	}
	switch strings.ToLower(getenv("TESSERA_OUTBOUND_ALLOW_LOOPBACK")) {
	case "1", "true", "yes":
		r.AllowLoopback = true
	}
	return r
}

// Defaults for connector clients: pages are larger and slower than the
// 5 s / 512 KiB defaults meant for discovery documents.
const (
	DefaultTimeout      = 30 * time.Second
	DefaultMaxBodyBytes = 16 << 20
)

// NewHTTPClient returns the SSRF-guarded client every connector must use. o
// carries the test hooks (RootCAs, Resolver) and limits; Env and
// AllowLoopback come from rt.
func NewHTTPClient(rt Runtime, o safehttp.Options) (*http.Client, error) {
	o.Env, o.AllowLoopback = rt.Env, rt.AllowLoopback
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	return safehttp.New(o)
}

var domainRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)

// ValidDomain reports whether host is a well-formed DNS name with at least two
// labels and an alphabetic top-level label (so never an IP literal).
func ValidDomain(host string) bool {
	host = strings.ToLower(host)
	return len(host) <= 253 && domainRE.MatchString(host)
}

// ParseBaseURL validates a customer-configured service URL: https only, a
// well-formed domain host, no user info, query or fragment. Plain http to a
// literal loopback address is accepted only in dev with the loopback exception.
// Private and link-local addresses are refused later, at connect time, by
// safehttp.
func ParseBaseURL(raw string, rt Runtime) (*url.URL, error) {
	if len(raw) > 512 {
		return nil, errors.New("base URL is too long")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, errors.New("base URL is not a valid URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("base URL must not contain user info, a query or a fragment")
	}
	host := u.Hostname()
	loop := false
	if a, err := netip.ParseAddr(host); err == nil && rt.Env == config.Dev && rt.AllowLoopback && a.IsLoopback() {
		loop = true
	}
	switch {
	case loop:
	case u.Scheme != "https":
		return nil, errors.New("base URL must be https")
	case !ValidDomain(host):
		return nil, errors.New("base URL host is not a well-formed domain name")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("base URL must be https")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// SameOrigin parses a server-supplied link (a next page, a delta link) and
// refuses it unless it is on the same scheme, host and port as base. The
// Authorization header would otherwise go wherever a response pointed.
func SameOrigin(base *url.URL, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("connsync: invalid page link")
	}
	if !strings.EqualFold(u.Scheme, base.Scheme) || !strings.EqualFold(u.Hostname(), base.Hostname()) || port(u) != port(base) {
		return nil, errors.New("connsync: page link leaves the configured host")
	}
	return u, nil
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return "443"
}

// Secret is a credential value. It never prints: %v, %s, %+v, %#v and JSON all
// show REDACTED. Use Reveal at the one place that sends it.
type Secret struct{ v string }

// NewSecret wraps a value.
func NewSecret(v string) Secret { return Secret{v} }

// Reveal returns the value.
func (s Secret) Reveal() string { return s.v }

// Empty reports whether no value is set.
func (s Secret) Empty() bool { return s.v == "" }

func (Secret) String() string               { return "REDACTED" }
func (Secret) GoString() string             { return "REDACTED" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"REDACTED"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte("REDACTED"), nil }
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "REDACTED") }

// maxSecretFile bounds a credential file (a PEM private key is about 2 KiB).
const maxSecretFile = 64 << 10

// ResolveSecret reads a credential from a reference. Today a reference is
// env:NAME (the process environment) or file:/absolute/path (a file such as a
// mounted Kubernetes or Docker secret). A literal credential is refused so it
// cannot sit in a config file or an operator's shell history by accident. The
// sealed and vault references of the connection credential store plug in here
// when that store lands.
func ResolveSecret(ref string, getenv func(string) string) (Secret, error) {
	kind, rest, ok := strings.Cut(ref, ":")
	if !ok || rest == "" {
		return Secret{}, errors.New("secret reference must be env:NAME or file:/path")
	}
	switch kind {
	case "env":
		v := strings.TrimSpace(getenv(rest))
		if v == "" {
			return Secret{}, fmt.Errorf("secret reference env:%s is empty or unset", rest)
		}
		return Secret{v}, nil
	case "file":
		if !filepath.IsAbs(rest) {
			return Secret{}, errors.New("secret reference file: needs an absolute path")
		}
		f, err := os.Open(filepath.Clean(rest)) // #nosec G304 -- operator-chosen path
		if err != nil {
			return Secret{}, errors.New("cannot read the secret file")
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
		if err != nil || len(b) > maxSecretFile {
			return Secret{}, errors.New("cannot read the secret file (unreadable or over 64 KiB)")
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return Secret{}, errors.New("the secret file is empty")
		}
		return Secret{v}, nil
	}
	return Secret{}, fmt.Errorf("secret reference kind %q is not supported (use env: or file:)", kind)
}
