package connsync

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

// Runtime is what a connector needs from the process configuration: the
// environment and whether the dev loopback exception is on.
type Runtime struct {
	Env           string // config.Dev or config.Prod
	AllowLoopback bool
}

// RuntimeFromConfig takes the environment and the loopback exception from the
// configuration config.Load validated (config.Prod refuses the exception), the
// same source safehttp.ForConfig uses. Anything but "prod" has the dev rules;
// a Config that Load did not return gets the production rules.
func RuntimeFromConfig(c *config.Config) Runtime {
	env, loopback, ok := c.Outbound()
	if !ok || env != config.Dev {
		return Runtime{Env: config.Prod}
	}
	return Runtime{Env: config.Dev, AllowLoopback: loopback}
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

// ErrCredentialFormat marks a connection credential that is not in the shape the
// connector reads (not JSON, not a PEM key, the wrong kind of key). Readiness
// shows a failed credential check for it instead of "no prober".
var ErrCredentialFormat = errors.New("the stored credential is not in the expected format")

type credentialFormatError struct{ hint string }

func (e credentialFormatError) Error() string        { return e.hint }
func (e credentialFormatError) Is(target error) bool { return target == ErrCredentialFormat }

// CredentialFormat returns an error that matches ErrCredentialFormat. hint is
// fixed text naming the expected format; it is shown to the admin and logged, so
// it must be a literal and never include a part of the credential or a parser
// error (parsers can quote the input).
func CredentialFormat(hint string) error { return credentialFormatError{hint} }

// CredentialFormatHint returns the fixed hint of an ErrCredentialFormat error
// (and only that: text a caller wrapped around it is dropped).
func CredentialFormatHint(err error) (string, bool) {
	var e credentialFormatError
	if errors.As(err, &e) {
		return e.hint, true
	}
	return "", false
}
