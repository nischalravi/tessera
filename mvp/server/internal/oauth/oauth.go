// Package oauth is Tessera's OAuth 2.0 authorization server for the CLI and
// for machine clients (design docs/design/phase-0-platform-security.md §6,
// §9.3, §9.5, §10, §19 PR10 and PR11).
//
// Each tenant is its own issuer, PUBLIC_URL/t/{slug}. It serves the device
// authorization grant (RFC 8628) and the refresh-token grant for the CLI, both
// sender-constrained with DPoP (RFC 9449, package dpop), and the client
// credentials grant for machine clients, which authenticate with a signed JWT
// (private_key_jwt, RFC 7523: clientauth.go) and use DPoP unless the client is
// registered without it. It issues JWT access tokens (RFC 9068) signed with the
// tenant's own ES256 key (internal/keys), and answers token introspection
// (RFC 7662) for machine clients allowed to ask (introspect.go).
//
// Library choice (the PR10 spike rule, §19): the grants are hand-written on
// go-jose, the §6 fallback, not on zitadel/oidc. zitadel/oidc v3.51.13
// downloads and builds, but its op.Storage is a 38-method interface that owns
// the token endpoint and signing keys, which would put the three pieces this
// PR must own outside our code: refresh-token rotation and reuse detection
// (left to the storage implementation), DPoP validation before issuance
// (RFC 9449 is not implemented in it) and the per-tenant key set of
// internal/keys. An adapter would have been a second, thicker layer over the
// same hand-written code. go-jose is already a dependency (§6), so the
// fallback adds none.
//
// Files: oauth.go (Service, helpers), tokens.go (mint and verify access
// tokens), device.go (device authorization, user-code lookup and approval),
// grants.go (the token endpoint: device_code, refresh_token and
// client_credentials), clientauth.go (private_key_jwt assertions and the
// registered key sets), introspect.go (RFC 7662), routes.go (the public routes
// and the RFC 8414 and 9728 documents), clients.go (the first-party CLI
// client).
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Grant types and well-known values.
const (
	GrantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	GrantRefresh    = "refresh_token"
	// GrantClientCredentials is the machine clients' grant (RFC 6749 §4.4).
	GrantClientCredentials = "client_credentials"
	// ScopeIntrospect is held by a machine client that may call the
	// introspection endpoint. It is a capability of the client's registration,
	// not an API scope: it covers no permission (auth.ScopeSetOf drops it).
	ScopeIntrospect = "tessera:introspect"

	// CLIClientID is the first-party CLI client every tenant has.
	CLIClientID = "tessera-cli"
	// DefaultScope is what a device authorization without a scope asks for.
	DefaultScope = "tessera:read"
)

// Lifetimes (§10.2).
const (
	DefaultAccessTokenTTL = 600 * time.Second
	AdminAccessTokenTTL   = 300 * time.Second
	DefaultDeviceCodeTTL  = 300 * time.Second
	DeviceInterval        = 5 // seconds; slow_down adds 5 (RFC 8628 §3.5)
	// RefreshIdle is the idle lifetime of a refresh token; the absolute
	// lifetime is the CLI session's.
	RefreshIdle = 12 * time.Hour
)

// Config configures a Service.
type Config struct {
	DB     *store.DB
	Sealer *seal.Sealer // KEK: opens the signing keys and derives the DPoP nonce key
	Clock  func() time.Time
	// PublicURL is TESSERA_PUBLIC_URL without a trailing slash: the base of
	// every issuer and of the htu a DPoP proof is bound to (never built from
	// the Host header).
	PublicURL string
	// APIAudience is TESSERA_API_AUDIENCE: the aud of access tokens.
	APIAudience string
	// AccessTokenTTL (TESSERA_AT_TTL_SECONDS) defaults to 600 s; a token whose
	// scope includes tessera:admin lives at most AdminAccessTokenTTL.
	AccessTokenTTL time.Duration
	// DeviceCodeTTL (TESSERA_DEVICE_CODE_TTL_SECONDS) defaults to 300 s.
	DeviceCodeTTL time.Duration
	// RSNonce requires a DPoP server nonce at the resource server too
	// (TESSERA_DPOP_RS_NONCE).
	RSNonce bool
	Log     *slog.Logger
	// ClientIP is the rate-limit key and recorded address of a request (the
	// API passes its trusted-proxy aware function); nil: the TCP peer.
	ClientIP func(*http.Request) string
}

// Service is the authorization server.
type Service struct {
	cfg      Config
	db       *store.DB
	dpop     *dpop.Validator
	devAuth  *ratelimit.Limiter // device_authorization: 10 per minute per IP
	lockouts *lookupLockouts    // user-code lookups: 5 failures per session per 10 minutes
}

// New builds a Service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Clock == nil || cfg.PublicURL == "" || cfg.APIAudience == "" {
		return nil, errors.New("oauth: Config needs DB, Clock, PublicURL and APIAudience")
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = DefaultAccessTokenTTL
	}
	if cfg.DeviceCodeTTL <= 0 {
		cfg.DeviceCodeTTL = DefaultDeviceCodeTTL
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.ClientIP == nil {
		cfg.ClientIP = peerAddr
	}
	v := &dpop.Validator{Replay: storeReplay{cfg.DB}}
	if cfg.Sealer != nil {
		key, err := cfg.Sealer.DeriveKey("dpop-nonce", 32)
		if err != nil {
			return nil, err
		}
		v.NonceKey = key
	}
	return &Service{cfg: cfg, db: cfg.DB, dpop: v, devAuth: ratelimit.New(6*time.Second, 10, 10000),
		lockouts: newLookupLockouts()}, nil
}

func (s *Service) now() time.Time { return s.cfg.Clock().UTC() }

// Issuer is the issuer identifier of tenant slug.
func (s *Service) Issuer(slug string) string { return s.cfg.PublicURL + "/t/" + slug }

func (s *Service) endpoint(slug, name string) string { return s.Issuer(slug) + "/oauth/" + name }

func peerAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// storeReplay is the DPoP replay cache: the global replay_cache table.
type storeReplay struct{ db *store.DB }

func (r storeReplay) UseOnce(ctx context.Context, keyHash string, now, expires time.Time) error {
	err := r.db.InSystem(ctx, "dpop replay", func(s *store.SystemTx) error {
		return s.UseOnce(store.ReplayDPoPJTI, keyHash, now, expires)
	})
	if errors.Is(err, store.ErrDuplicate) {
		return dpop.ErrReplay
	}
	return err
}

// ---------------------------------------------------------------- tenants

// tenantBySlug resolves an active tenant; ok is false for an unknown,
// suspended or reserved one (the caller answers 404, the same for all).
func (s *Service) tenantBySlug(ctx context.Context, slug string) (t store.Tenant, ok bool, err error) {
	if !store.ValidSlug(slug) {
		return t, false, nil
	}
	err = s.db.ReadSystem(ctx, "oauth tenant", func(st *store.SystemTx) error {
		var err error
		t, err = st.TenantBySlug(slug)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return t, false, nil
	}
	if err != nil {
		return t, false, err
	}
	return t, t.Status == "active" && t.ID != tenancy.Platform, nil
}

// attribute puts the request's events (its http.request event and the domain
// events of the transactions opened with the returned context) on the chain of
// the tenant whose endpoint it is, as an anonymous OAuth client until the
// caller authenticates a user.
func attribute(ctx context.Context, t tenancy.ID) context.Context {
	ctx = audit.SetPrincipal(ctx, audit.Principal{Tenant: t, Actor: store.AuditActor{Type: store.ActorAnonymous}})
	audit.SetAnonymous(ctx, "oauth_client")
	return ctx
}

// DeviceGrantEnabled reads tenant.settings.device_grant_enabled (default
// true). Settings that cannot be read fail closed: the grant is off.
func DeviceGrantEnabled(settings string) bool {
	if settings == "" {
		return true
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal([]byte(settings), &v); err != nil || v == nil {
		return false
	}
	b, ok := v["device_grant_enabled"]
	if !ok {
		return true
	}
	var on bool
	if err := json.Unmarshal(b, &on); err != nil {
		return false
	}
	return on
}

// ---------------------------------------------------------------- responses

// writeJSON writes a JSON body that must not be cached (token responses).
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = w.Write(b) // #nosec G705 -- JSON-encoded body served as application/json with nosniff
}

// oauthError is the RFC 6749 §5.2 error response.
func oauthError(w http.ResponseWriter, status int, code, description string) {
	body := map[string]string{"error": code}
	if description != "" {
		body["error_description"] = description
	}
	writeJSON(w, status, body)
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
}

func serverError(w http.ResponseWriter, log *slog.Logger, r *http.Request, err error) {
	log.Error("oauth request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// formBody parses a form-encoded request body of at most 16 KiB.
func formBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use POST")
		return false
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body must be application/x-www-form-urlencoded")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the request body is not a valid form")
		return false
	}
	return true
}

// formValue returns a parameter that must appear at most once.
func formValue(r *http.Request, name string) (string, bool) {
	v := r.PostForm[name]
	switch len(v) {
	case 0:
		return "", true
	case 1:
		return v[0], true
	}
	return "", false
}

// hashHex is the stored form of a bearer secret.
func hashHex(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------- lookup lockouts

// Device user-code lookups are brute-force limited per session (§9.3): five
// failed lookups within ten minutes lock that session out of lookups and
// approvals for ten minutes. The state is in process memory (bounded), like
// the other limiters; a restart gives a session a fresh allowance.
const (
	lookupMaxFailures = 5
	lookupWindow      = 10 * time.Minute
	lookupLockout     = 10 * time.Minute
	lookupMaxKeys     = 10000
)

type lockoutEntry struct {
	failures    []time.Time
	lockedUntil time.Time
}

type lookupLockouts struct {
	mu sync.Mutex
	m  map[string]*lockoutEntry
}

func newLookupLockouts() *lookupLockouts { return &lookupLockouts{m: map[string]*lockoutEntry{}} }

// locked reports whether key is locked out at now and, if so, until when.
func (l *lookupLockouts) locked(key string, now time.Time) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.m[key]; ok && now.Before(e.lockedUntil) {
		return e.lockedUntil, true
	}
	return time.Time{}, false
}

// fail records a failed lookup; locked is true when this failure starts the
// lockout (the caller audits it once).
func (l *lookupLockouts) fail(key string, now time.Time) (until time.Time, locked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) >= lookupMaxKeys {
		for k, e := range l.m {
			if !now.Before(e.lockedUntil) && (len(e.failures) == 0 || now.Sub(e.failures[len(e.failures)-1]) > lookupWindow) {
				delete(l.m, k)
			}
		}
		for k := range l.m { // still full: evict one entry rather than grow without bound
			if len(l.m) < lookupMaxKeys {
				break
			}
			delete(l.m, k)
		}
	}
	e := l.m[key]
	if e == nil {
		e = &lockoutEntry{}
		l.m[key] = e
	}
	keep := e.failures[:0]
	for _, t := range e.failures {
		if now.Sub(t) <= lookupWindow {
			keep = append(keep, t)
		}
	}
	e.failures = append(keep, now)
	if len(e.failures) >= lookupMaxFailures {
		e.lockedUntil = now.Add(lookupLockout)
		e.failures = nil
		return e.lockedUntil, true
	}
	return time.Time{}, false
}

// A successful lookup deliberately does not clear the failures: anyone can
// start a device flow of their own and would otherwise reset the count with a
// valid code between guesses.
