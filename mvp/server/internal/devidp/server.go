// Package devidp is Tessera's development and test identity provider: a
// mock OpenID Connect issuer (and, from PR9, a SAML IdP) that lets Tessera be
// built and tested without a real Okta or Entra tenant
// (docs/design/phase-0-platform-security.md §18.5).
//
// It is never part of the production API: cmd/tessera does not import it
// (internal/archtest proves that), cmd/tessera-devidp refuses to start unless
// TESSERA_ENV is dev or test, and New refuses TESSERA_ENV=prod.
//
// Behaviour, in short:
//   - discovery, JWKS, authorization code flow with PKCE (S256 only, always
//     required), client_secret_basic or private_key_jwt at the token endpoint;
//   - an HTML sign-in page where the user, the authenticator (passkey,
//     hardware key, password + OTP, password) and the vendor emulation (Okta,
//     Entra, generic) are picked; acr, amr and acrs follow the emulated vendor
//     (profiles.go);
//   - an IdP session cookie, so a second authorization is single sign-on
//     unless prompt=login or max_age forces the page again, which updates
//     auth_time;
//   - fault injection for negative relying-party tests (faults.go).
package devidp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Lifetimes and limits.
const (
	pendingTTL     = 10 * time.Minute // sign-in page to submit
	codeTTL        = 60 * time.Second // authorization code
	idTokenTTL     = 5 * time.Minute
	accessTokenTTL = 5 * time.Minute
	sessionTTL     = 12 * time.Hour // IdP SSO session
	maxEntries     = 10000          // per in-memory store
	maxFormBytes   = 64 << 10
	maxMaxAge      = 366 * 24 * 60 * 60
	rsaKeyBits     = 2048
	sessionCookie  = "devidp_session"
)

// Client is a relying party registered with the dev IdP.
type Client struct {
	ID string
	// Secret enables client_secret_basic. Empty disables it.
	Secret string
	// JWKS enables private_key_jwt (RFC 7523) with these public keys. Nil
	// disables it.
	JWKS *jose.JSONWebKeySet
	// RedirectURIs are matched exactly, except that "*" matches a port or one
	// path segment (see matchRedirect), so
	// "http://127.0.0.1:*/api/auth/oidc/*/callback" covers every connection.
	RedirectURIs []string
	// PostLogoutRedirectURIs are matched exactly.
	PostLogoutRedirectURIs []string
}

// Config configures a Server.
type Config struct {
	// Issuer is the exact issuer URL, for example http://127.0.0.1:8001. All
	// endpoints are served under it.
	Issuer string
	// Key signs ID tokens (RS256). Nil generates an in-memory key.
	Key *rsa.PrivateKey
	// Users; nil loads the embedded users.yaml.
	Users   []User
	Clients []Client
	// DefaultProfile is preselected on the sign-in page; "" means okta.
	DefaultProfile Profile
	// Faults enables fault injection (fault= on /authorize and /_faults).
	Faults bool
	// Now is the clock; nil means time.Now.
	Now    func() time.Time
	Logger *slog.Logger
	// SAMLACS are the AssertionConsumerServiceURL patterns ("*" matches a
	// port or one path segment); nil allows http loopback and localhost
	// /api/auth/saml/*/acs.
	SAMLACS []string
}

// Server is a dev IdP. Create it with New and serve Handler.
type Server struct {
	issuer         string
	key            *rsa.PrivateKey
	attackerKey    *rsa.PrivateKey // signs jku_header tokens; served at faultJKUPath
	kid            string
	pubPEM         []byte // HMAC key of the hs256_with_pubkey fault
	users          []User
	clients        map[string]*Client
	defaultProfile Profile
	faults         bool
	now            func() time.Time
	log            *slog.Logger

	samlCert        []byte   // DER, derived from key
	samlACS         []string // ACS URL patterns AuthnRequests may name
	samlPending     ttlStore[pendingSAML]
	lastAssertionID string // guarded by mu; the replay fault reuses it

	pending  ttlStore[pendingAuthz]
	codes    ttlStore[authCode]
	sessions ttlStore[idpSession]
	tokens   ttlStore[accessGrant]
	github   ttlStore[githubGrant]
	jtis     ttlStore[struct{}]

	mu    sync.Mutex
	fault Fault // set by POST /_faults
}

// CheckEnv is the start-up guard of the standalone binary: the dev IdP runs
// only when TESSERA_ENV is exactly "dev" or "test", so an unset or mistyped
// value fails closed (§18.4).
func CheckEnv(env string) error {
	if env == "dev" || env == "test" {
		return nil
	}
	return fmt.Errorf("the dev IdP runs only with TESSERA_ENV=dev or test (got %q); it must never run in production", env)
}

// New builds a Server. It refuses to construct one when TESSERA_ENV=prod,
// whoever the caller is.
func New(cfg Config) (*Server, error) {
	if os.Getenv("TESSERA_ENV") == "prod" {
		return nil, errors.New("devidp: refusing to run with TESSERA_ENV=prod")
	}
	iss, err := url.Parse(cfg.Issuer)
	if err != nil || (iss.Scheme != "http" && iss.Scheme != "https") || iss.Host == "" ||
		iss.RawQuery != "" || iss.Fragment != "" || strings.HasSuffix(cfg.Issuer, "/") {
		return nil, fmt.Errorf("devidp: issuer %q must be an absolute http(s) URL without query, fragment or trailing slash", cfg.Issuer)
	}
	s := &Server{
		issuer:         cfg.Issuer,
		key:            cfg.Key,
		users:          cfg.Users,
		clients:        map[string]*Client{},
		defaultProfile: cfg.DefaultProfile,
		faults:         cfg.Faults,
		now:            cfg.Now,
		log:            cfg.Logger,
		samlACS:        cfg.SAMLACS,
	}
	if s.samlACS == nil {
		s.samlACS = []string{defaultSAMLACSPattern1, defaultSAMLACSPattern2}
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.defaultProfile == "" {
		s.defaultProfile = ProfileOkta
	}
	if !slices.Contains(Profiles(), s.defaultProfile) {
		return nil, fmt.Errorf("devidp: unknown profile %q (have %v)", s.defaultProfile, Profiles())
	}
	if s.users == nil {
		if s.users, err = DefaultUsers(); err != nil {
			return nil, err
		}
	}
	if s.key == nil {
		if s.key, err = GenerateKey(); err != nil {
			return nil, err
		}
	}
	if s.faults {
		if s.attackerKey, err = GenerateKey(); err != nil {
			return nil, err
		}
	}
	if s.key.N.BitLen() < rsaKeyBits {
		return nil, fmt.Errorf("devidp: signing key must be at least %d bits", rsaKeyBits)
	}
	if err := s.makeSAMLCert(); err != nil {
		return nil, fmt.Errorf("devidp: SAML certificate: %w", err)
	}
	jwk := jose.JSONWebKey{Key: s.key.Public()}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	s.kid = base64.RawURLEncoding.EncodeToString(tp)
	der, err := x509.MarshalPKIXPublicKey(s.key.Public())
	if err != nil {
		return nil, err
	}
	s.pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	for i := range cfg.Clients {
		c := cfg.Clients[i]
		if c.ID == "" || (c.Secret == "" && c.JWKS == nil) || len(c.RedirectURIs) == 0 {
			return nil, fmt.Errorf("devidp: client %q needs an id, a secret or JWKS, and redirect URIs", c.ID)
		}
		if _, dup := s.clients[c.ID]; dup {
			return nil, fmt.Errorf("devidp: duplicate client %q", c.ID)
		}
		s.clients[c.ID] = &c
	}
	return s, nil
}

// GenerateKey creates a new RS256 signing key.
func GenerateKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, rsaKeyBits) }

// Issuer returns the issuer URL.
func (s *Server) Issuer() string { return s.issuer }

// KeyID returns the kid of the signing key (its RFC 7638 thumbprint).
func (s *Server) KeyID() string { return s.kid }

// JWKS returns the public key set served at /jwks.
func (s *Server) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: s.key.Public(), KeyID: s.kid, Algorithm: string(jose.RS256), Use: "sig",
	}}}
}

// Users returns a copy of the configured users.
func (s *Server) Users() []User { return slices.Clone(s.users) }

// SetFault sets the fault applied to every later authorization (as POST
// /_faults does); FaultNone clears it. It fails when faults are disabled.
func (s *Server) SetFault(f Fault) error {
	if !s.faults {
		return errors.New("devidp: fault injection is disabled")
	}
	if _, err := ParseFault(string(f)); err != nil {
		return err
	}
	s.mu.Lock()
	s.fault = f
	s.mu.Unlock()
	return nil
}

func (s *Server) currentFault() Fault {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fault
}

// Handler returns the HTTP handler serving every endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /jwks", s.handleJWKS)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /authorize", s.handleAuthorizeSubmit)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /userinfo", s.handleUserinfo)
	mux.HandleFunc("POST /userinfo", s.handleUserinfo)
	mux.HandleFunc("GET /logout", s.handleLogout)
	mux.HandleFunc("GET "+pathGitHubAuthorize, s.handleGitHubAuthorize)
	mux.HandleFunc("POST "+pathGitHubToken, s.handleGitHubToken)
	mux.HandleFunc("GET "+pathGitHubUser, s.handleGitHubUser)
	mux.HandleFunc("GET "+pathGitHubEmails, s.handleGitHubEmails)
	mux.HandleFunc("GET "+samlEntityPath, s.handleSAMLMetadata)
	mux.HandleFunc("GET "+samlSSOPath, s.handleSAMLSSO)
	mux.HandleFunc("POST "+samlSSOPath, s.handleSAMLSubmit)
	if s.faults {
		mux.HandleFunc("GET "+faultJKUPath, s.handleAttackerJWKS)
		mux.HandleFunc("GET /_faults", s.handleGetFault)
		mux.HandleFunc("POST /_faults", s.handleSetFault)
	}
	mux.HandleFunc("GET /{$}", s.handleIndex)
	prefix := ""
	if u, err := url.Parse(s.issuer); err == nil {
		prefix = strings.TrimSuffix(u.Path, "/")
	}
	var h http.Handler = mux
	if prefix != "" {
		h = http.StripPrefix(prefix, mux)
	}
	return securityHeaders(h)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ttlStore is a bounded in-memory map whose entries expire.
type ttlStore[T any] struct {
	mu sync.Mutex
	m  map[string]ttlEntry[T]
}

type ttlEntry[T any] struct {
	v   T
	exp time.Time
}

var errStoreFull = errors.New("devidp: too many pending entries")

func (s *ttlStore[T]) put(k string, v T, exp, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(k, v, exp, now)
}

// putNew stores an entry only if the key is absent or expired; it reports
// whether it did (replay detection).
func (s *ttlStore[T]) putNew(k string, v T, exp, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[k]; ok && now.Before(e.exp) {
		return false, nil
	}
	return true, s.putLocked(k, v, exp, now)
}

func (s *ttlStore[T]) putLocked(k string, v T, exp, now time.Time) error {
	if s.m == nil {
		s.m = map[string]ttlEntry[T]{}
	}
	if len(s.m) >= maxEntries {
		for key, e := range s.m {
			if !now.Before(e.exp) {
				delete(s.m, key)
			}
		}
		if len(s.m) >= maxEntries {
			return errStoreFull
		}
	}
	s.m[k] = ttlEntry[T]{v: v, exp: exp}
	return nil
}

// get returns an unexpired entry.
func (s *ttlStore[T]) get(k string, now time.Time) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	if !ok || !now.Before(e.exp) {
		var zero T
		return zero, false
	}
	return e.v, true
}

// take removes an entry and returns it if it had not expired: single use.
func (s *ttlStore[T]) take(k string, now time.Time) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	delete(s.m, k)
	if !ok || !now.Before(e.exp) {
		var zero T
		return zero, false
	}
	return e.v, true
}

func (s *ttlStore[T]) del(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
}

// matchRedirect reports whether uri matches a registered pattern, where "*"
// matches one or more RFC 3986 unreserved characters (letters, digits, '-',
// '.', '_', '~'): enough for a port or one path segment, never '/', '?', '#',
// '@' or ':', so a wildcard cannot change the host or add userinfo. A
// wildcard never matches the dot segments "." or "..", which a browser would
// resolve to a different, unregistered path.
func matchRedirect(pattern, uri string) bool {
	head, tail, wild := strings.Cut(pattern, "*")
	if !wild {
		return pattern == uri
	}
	if !strings.HasPrefix(uri, head) {
		return false
	}
	rest := uri[len(head):]
	for i := 1; i <= len(rest); i++ {
		if !unreserved(rest[i-1]) {
			return false
		}
		if seg := rest[:i]; seg != "." && seg != ".." && matchRedirect(tail, rest[i:]) {
			return true
		}
	}
	return false
}

func unreserved(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || strings.IndexByte("-._~", b) >= 0
}

func (c *Client) redirectAllowed(uri string) bool {
	for _, p := range c.RedirectURIs {
		if matchRedirect(p, uri) {
			return true
		}
	}
	return false
}
