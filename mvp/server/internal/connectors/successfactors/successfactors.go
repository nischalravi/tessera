// Package successfactors is the production read connector for SAP
// SuccessFactors Employee Central as an authoritative HR source, over the
// SuccessFactors OData v2 API.
//
// It reads User (login, name, e-mail, status), EmpEmployment (start and end
// dates), EmpJob (department, title, manager, location, cost center, legal
// entity) and PerPerson (the person key and, for people without a User row,
// the name). It is read-only: every request is a GET, except the OAuth token
// request of the SAML bearer flow. There is no write-back.
//
// Mapping onto Tessera's model, so ingest, correlation and the joiner / mover
// / leaver flow are reused (the same shape as the Workday source):
//
//	person (employment)  -> identity (human) keyed by the person id
//	                        (personIdExternal), with the work e-mail for
//	                        correlation, and a successfactors account keyed by
//	                        the user id; terminated once the end date has come
//	department           -> group (kind department); the account is -member_of-> it
//	employment start     -> hris event "joiner"
//	employment end       -> hris event "leaver"
//	department / manager
//	change of the job    -> hris event "mover"
//
// Effective dating follows Workday's rule: nothing is applied early. A person
// whose start date is still ahead is not an identity yet (only a pending joiner
// event exists), and an end date still ahead leaves the person active with a
// pending leaver event. SuccessFactors marks an open end with 9999-12-31, which
// is read as "no end".
//
// Authentication is either HTTP Basic (user@company id) or an OAuth 2.0 SAML
// bearer assertion: Tessera signs an assertion with the key and certificate it
// holds sealed and exchanges it for an access token at /oauth/token.
//
// The API host must be one of the documented SuccessFactors data-center
// domains (HostAllowlist). The only exception is a loopback address in a dev
// runtime with the loopback exception on, which is how tests reach a fake; the
// runtime is built from the validated configuration, which refuses that
// exception in production (internal/config).
//
// Paging is server-side: every collection is followed through __next, each link
// checked to stay on the configured host. Every read is a full read; the
// endpoint paths are fixed (/odata/v2).
package successfactors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the graph system name.
const System = "successfactors"

// Authentication modes.
const (
	AuthBasic = "basic"
	AuthSAML  = "saml_bearer"
)

const (
	odataRoot = "/odata/v2"
	tokenPath = "/oauth/token" // #nosec G101 -- an endpoint path, not a credential
)

// HostAllowlist are the documented SuccessFactors data-center domains (a
// pattern matches any subdomain, never the apex). The readiness template's
// host_allowlist holds the same list (a test compares them).
var HostAllowlist = []string{"*.successfactors.com", "*.successfactors.eu", "*.sapsf.com", "*.sapsf.cn", "*.sapsf.eu"}

// HostAllowed reports whether host is on HostAllowlist.
func HostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range HostAllowlist {
		if suffix := p[1:]; strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

var (
	companyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	userRE    = regexp.MustCompile(`^[^\x00-\x1f\x7f:]{1,128}$`)
	clientRE  = regexp.MustCompile(`^[^\x00-\x1f\x7f\s]{1,256}$`)
	entityRE  = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,64}$`)
)

// Config configures one SuccessFactors company.
type Config struct {
	// BaseURL is the API server of the company's data center, for example
	// https://api4.successfactors.com (no path).
	BaseURL string
	// CompanyID is the SuccessFactors company id.
	CompanyID string
	// Auth is AuthBasic (default) or AuthSAML.
	Auth string
	// Username is the API user's id. Basic sends it as user@company id; the SAML
	// assertion is issued for it.
	Username string
	// Password is the API user's password (basic).
	Password connsync.Secret
	// ClientID is the registered OAuth client's API key (SAML bearer).
	ClientID string
	// PrivateKey is a PEM bundle holding the RSA private key and the X.509
	// certificate registered on the OAuth client (SAML bearer).
	PrivateKey connsync.Secret
	// LegalEntity, when set, reads only the jobs of that legal entity (company).
	LegalEntity string
	// EmitIdentities emits an identity per person (on by default: this is an HR
	// source, and the other connectors should turn their own off).
	EmitIdentities bool
	// EventWindow is how far back an event still counts as new (default 30 days).
	EventWindow time.Duration
}

// Connector implements connectors.Connector for SuccessFactors.
type Connector struct {
	cfg  Config
	base *url.URL
	api  *connsync.Client
	tok  *samlSource
	now  func() time.Time
}

// New builds a connector. hc is the server's shared safehttp client.
func New(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Connector, error) {
	if cfg.Auth == "" {
		cfg.Auth = AuthBasic
	}
	if cfg.Auth != AuthBasic && cfg.Auth != AuthSAML {
		return nil, errors.New("successfactors: auth must be basic or saml_bearer")
	}
	if !companyRE.MatchString(cfg.CompanyID) {
		return nil, errors.New("successfactors: the company id is missing or not a plain id")
	}
	if !userRE.MatchString(cfg.Username) {
		return nil, errors.New("successfactors: the API user is missing or malformed")
	}
	switch cfg.Auth {
	case AuthBasic:
		if cfg.Password.Empty() {
			return nil, errors.New("successfactors: a password is required for basic authentication")
		}
	case AuthSAML:
		if !clientRE.MatchString(cfg.ClientID) {
			return nil, errors.New("successfactors: an OAuth client id (API key) is required for the SAML bearer flow")
		}
		if cfg.PrivateKey.Empty() {
			return nil, errors.New("successfactors: a private key and certificate are required for the SAML bearer flow")
		}
		if _, _, err := parseKeyBundle(cfg.PrivateKey.Reveal()); err != nil {
			return nil, err
		}
	}
	if cfg.LegalEntity != "" && !entityRE.MatchString(cfg.LegalEntity) {
		return nil, errors.New("successfactors: the legal entity must be 1 to 64 printable characters")
	}
	if cfg.EventWindow == 0 {
		cfg.EventWindow = 30 * 24 * time.Hour
	}
	if cfg.EventWindow < 24*time.Hour {
		return nil, errors.New("successfactors: the event window must be at least 24h")
	}
	base, err := connsync.ParseBaseURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("successfactors: base URL: %w", err)
	}
	if base.Path != "" {
		return nil, errors.New("successfactors: base URL must be a host without a path")
	}
	if !loopbackAllowed(base, rt) && (!HostAllowed(base.Hostname()) || base.Port() != "") {
		return nil, fmt.Errorf("successfactors: the API host must be a SuccessFactors data-center host (%s)", strings.Join(HostAllowlist, ", "))
	}
	if hc == nil {
		return nil, errors.New("successfactors: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	c := &Connector{cfg: cfg, base: base, now: now}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{
		"Accept": {"application/json"}, "User-Agent": {"tessera-connector/successfactors"}}}
	switch cfg.Auth {
	case AuthBasic:
		auth := basicHeader(cfg)
		c.api.Authorize = func(context.Context) (string, error) { return auth, nil }
	case AuthSAML:
		if c.tok, err = newSAMLSource(cfg, base, c.api, now); err != nil {
			return nil, err
		}
		c.api.Authorize = c.tok.authorization
		c.api.OnUnauthorized = c.tok.invalidate
	}
	return c, nil
}

// loopbackAllowed is the dev and test exception: a literal loopback address
// when the runtime is dev with the loopback exception on. Production never has
// it (config.Load refuses OUTBOUND_ALLOW_LOOPBACK there, and a runtime that did
// not come from a loaded configuration has the production rules).
func loopbackAllowed(u *url.URL, rt connsync.Runtime) bool {
	a, err := netip.ParseAddr(u.Hostname())
	return err == nil && a.IsLoopback() && rt.Env == config.Dev && rt.AllowLoopback
}

// FromEnv builds the connector from TESSERA_SUCCESSFACTORS_* variables (the
// mapping a governed connection uses, with the credential behind an env:
// reference):
//
//	TESSERA_SUCCESSFACTORS_BASE_URL      API server, https://api4.successfactors.com
//	TESSERA_SUCCESSFACTORS_COMPANY_ID    company id
//	TESSERA_SUCCESSFACTORS_AUTH          basic (default) or saml_bearer
//	TESSERA_SUCCESSFACTORS_USER          API user id
//	TESSERA_SUCCESSFACTORS_PASSWORD      reference to the password (basic): file:/abs/path or env:NAME
//	TESSERA_SUCCESSFACTORS_CLIENT_ID     OAuth client API key (saml_bearer)
//	TESSERA_SUCCESSFACTORS_PRIVATE_KEY   reference to the PEM key and certificate (saml_bearer)
//	TESSERA_SUCCESSFACTORS_LEGAL_ENTITY  optional: read one legal entity only
//	TESSERA_SUCCESSFACTORS_EMIT_IDENTITIES  true (default) or false
//	TESSERA_SUCCESSFACTORS_EVENT_WINDOW  duration, default 720h (at least 24h)
func FromEnv(getenv func(string) string, now time.Time, rt connsync.Runtime, hc *http.Client) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	return New(cfg, rt, hc, func() time.Time { return time.Now().UTC() })
}

// ConfigFromEnv reads the configuration (see FromEnv).
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_SUCCESSFACTORS_"
	cfg := Config{BaseURL: getenv(p + "BASE_URL"), CompanyID: getenv(p + "COMPANY_ID"), Auth: getenv(p + "AUTH"),
		Username: getenv(p + "USER"), ClientID: getenv(p + "CLIENT_ID"), LegalEntity: getenv(p + "LEGAL_ENTITY"), EmitIdentities: true}
	if v := getenv(p + "EMIT_IDENTITIES"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, errors.New(p + "EMIT_IDENTITIES must be true or false")
		}
		cfg.EmitIdentities = b
	}
	if v := getenv(p + "EVENT_WINDOW"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 24*time.Hour {
			return cfg, errors.New(p + "EVENT_WINDOW must be a duration of at least 24h")
		}
		cfg.EventWindow = d
	}
	secret := func(name string) (connsync.Secret, error) {
		ref := getenv(p + name)
		if ref == "" {
			return connsync.Secret{}, fmt.Errorf("%s%s (a file: or env: reference) is required", p, name)
		}
		s, err := connsync.ResolveSecret(ref, getenv)
		if err != nil {
			return s, fmt.Errorf("%s%s: %w", p, name, err)
		}
		return s, nil
	}
	var err error
	switch cfg.Auth {
	case "", AuthBasic:
		cfg.Password, err = secret("PASSWORD")
	case AuthSAML:
		cfg.PrivateKey, err = secret("PRIVATE_KEY")
	}
	return cfg, err
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "SAP SuccessFactors" }
func (*Connector) TypeName() string    { return "SuccessFactorsConnector" }
