package oauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

// fakeClock is the server's and the tests' clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var (
	tenantAID = tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	tenantBID = tenancy.MustParse("00000000-0000-4000-8000-0000000000b1")
)

const (
	slugA = "tenant-a"
	slugB = "tenant-b"
)

// harness is an authorization server and a small API in front of a real
// store: the OAuth routes, the device lookup and approve routes, and
// /api/whoami, which authenticates a request the way the API does
// (auth.Authenticator with the DPoP token path).
type harness struct {
	tb     testing.TB
	db     *store.DB
	sealer *seal.Sealer
	clock  *fakeClock
	svc    *Service
	srv    *httptest.Server
	authn  *auth.Authenticator
	mux    http.Handler
}

func newHarness(tb testing.TB, mutate ...func(*Config)) *harness {
	tb.Helper()
	h := &harness{tb: tb, db: testkit.Open(tb), clock: &fakeClock{t: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}}
	testkit.CreateTenant(tb, h.db, tenantAID, slugA)
	testkit.CreateTenant(tb, h.db, tenantBID, slugB)
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	var err error
	if h.sealer, err = seal.New(kek); err != nil {
		tb.Fatal(err)
	}
	ctx := context.Background()
	if err := keys.EnsureAll(ctx, h.db, h.sealer, h.clock.Now()); err != nil {
		tb.Fatal(err)
	}
	if err := EnsureCLIClients(ctx, h.db, h.clock.Now()); err != nil {
		tb.Fatal(err)
	}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }))
	tb.Cleanup(h.srv.Close)
	cfg := Config{DB: h.db, Sealer: h.sealer, Clock: h.clock.Now, PublicURL: h.srv.URL, APIAudience: h.srv.URL + "/api"}
	for _, m := range mutate {
		m(&cfg)
	}
	if h.svc, err = New(cfg); err != nil {
		tb.Fatal(err)
	}
	h.authn = &auth.Authenticator{DB: h.db, Clock: h.clock.Now, Tokens: h.svc}
	m := http.NewServeMux()
	m.Handle("/", h.svc.Handler())
	m.HandleFunc("POST /api/auth/device/lookup", h.session(h.svc.DeviceLookup))
	m.HandleFunc("POST /api/auth/device/approve", h.session(h.svc.DeviceApprove))
	m.HandleFunc("/api/whoami", h.whoami)
	h.mux = m
	return h
}

// session runs a device handler as the cookie session of the request.
func (h *harness) session(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _, err := h.authn.AuthenticateRequest(r)
		if err != nil || p == nil {
			auth.WriteDenial(w, &auth.Denial{Status: http.StatusUnauthorized, Error: "login_required"})
			return
		}
		// as the API's authorize step does: the principal, and the events are its
		sid := p.SessionID.String()
		ctx := audit.SetPrincipal(auth.WithPrincipal(r.Context(), p), audit.Principal{Tenant: p.TenantID,
			Actor: p.AuditActor(), SessionID: &sid})
		fn(w, r.WithContext(ctx))
	}
}

// whoami authenticates the request and describes its principal.
func (h *harness) whoami(w http.ResponseWriter, r *http.Request) {
	p, f, err := h.authn.AuthenticateRequest(r)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
	case p == nil:
		if f.Challenge != "" {
			w.Header().Set("WWW-Authenticate", f.Challenge)
		}
		if f.Nonce != "" {
			w.Header().Set("DPoP-Nonce", f.Nonce)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "login_required", "reason": f.Reason})
	default:
		var scopes []string
		for s := range p.Scopes {
			scopes = append(scopes, string(s))
		}
		slices.Sort(scopes)
		roles := []string{}
		for _, r := range p.ActiveRoles.Sorted() {
			roles = append(roles, string(r))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"user_id": p.UserID.String(), "tenant_id": p.TenantID.String(),
			"client_id": p.ClientID, "scopes": scopes, "active_roles": roles, "via": p.Via})
	}
}

func (h *harness) url(path string) string { return h.srv.URL + path }

func (h *harness) tenantID(slug string) tenancy.ID {
	if slug == slugB {
		return tenantBID
	}
	return tenantAID
}

// login signs a user in to a tenant at the current time.
func (h *harness) login(slug, email string, roles []auth.Role, c authtest.Ctx) authtest.Login {
	h.tb.Helper()
	return authtest.LoginAs(h.tb, h.db, h.tenantID(slug), authtest.User{Email: email, Roles: roles}, c, h.clock.Now())
}

// resp is a decoded HTTP response.
type resp struct {
	Status int
	Header http.Header
	Body   map[string]any
	Raw    string
}

func (r resp) str(k string) string { s, _ := r.Body[k].(string); return s }

func do(tb testing.TB, req *http.Request) resp {
	tb.Helper()
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req) // #nosec G107 G704 -- a request to the test server
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Header: res.Header, Raw: string(b)}
	_ = json.Unmarshal(b, &out.Body)
	return out
}

// browser sends a JSON request as a signed-in browser session.
func (h *harness) browser(l authtest.Login, method, path string, body any) resp {
	h.tb.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.url(path), rd)
	if err != nil {
		h.tb.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	l.Apply(req)
	return do(h.tb, req)
}

func (h *harness) postForm(path string, form url.Values, hdr map[string]string) resp {
	h.tb.Helper()
	req, err := http.NewRequest(http.MethodPost, h.url(path), strings.NewReader(form.Encode()))
	if err != nil {
		h.tb.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return do(h.tb, req)
}

func newKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

func jktOf(tb testing.TB, k *ecdsa.PrivateKey) string {
	tb.Helper()
	j, err := dpop.Thumbprint(&jose.JSONWebKey{Key: &k.PublicKey})
	if err != nil {
		tb.Fatal(err)
	}
	return j
}

// proof builds a DPoP proof for method and url with the current time.
func (h *harness) proof(k *ecdsa.PrivateKey, method, target, accessToken, nonce string) string {
	h.tb.Helper()
	return h.proofAt(k, method, target, accessToken, nonce, h.clock.Now())
}

func (h *harness) proofAt(k *ecdsa.PrivateKey, method, target, accessToken, nonce string, at time.Time) string {
	h.tb.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	if err != nil {
		h.tb.Fatal(err)
	}
	c := map[string]any{"jti": seal.RandomSecret(16), "htm": method, "htu": target, "iat": at.Unix()}
	if accessToken != "" {
		c["ath"] = dpop.AccessTokenHash(accessToken)
	}
	if nonce != "" {
		c["nonce"] = nonce
	}
	s, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		h.tb.Fatal(err)
	}
	return s
}

func (h *harness) nonce() string { return h.svc.dpop.NewNonce(h.clock.Now()) }

// tokenReq posts to the token endpoint of slug with a DPoP proof of k (and the
// current server nonce).
func (h *harness) tokenReq(slug string, form url.Values, k *ecdsa.PrivateKey) resp {
	h.tb.Helper()
	target := h.srv.URL + "/t/" + slug + "/oauth/token"
	return h.postForm("/t/"+slug+"/oauth/token", form, map[string]string{"DPoP": h.proof(k, "POST", target, "", h.nonce())})
}

// deviceStart is a device authorization response.
type deviceStart struct {
	DeviceCode, UserCode, VerificationURI string
	ExpiresIn, Interval                   int
	Raw                                   resp
}

func (h *harness) deviceAuthorize(slug string, extra url.Values) resp {
	h.tb.Helper()
	form := url.Values{"client_id": {CLIClientID}, "scope": {"tessera:read tessera:write"}}
	for k, v := range extra {
		form[k] = v
	}
	return h.postForm("/t/"+slug+"/oauth/device_authorization", form, nil)
}

func (h *harness) startDevice(slug string, extra url.Values) deviceStart {
	h.tb.Helper()
	r := h.deviceAuthorize(slug, extra)
	if r.Status != http.StatusOK {
		h.tb.Fatalf("device_authorization: %d %s", r.Status, r.Raw)
	}
	n := func(k string) int { f, _ := r.Body[k].(float64); return int(f) }
	return deviceStart{DeviceCode: r.str("device_code"), UserCode: r.str("user_code"), VerificationURI: r.str("verification_uri"),
		ExpiresIn: n("expires_in"), Interval: n("interval"), Raw: r}
}

func (h *harness) devicePoll(slug string, d deviceStart, k *ecdsa.PrivateKey) resp {
	h.tb.Helper()
	return h.tokenReq(slug, url.Values{"grant_type": {GrantDeviceCode}, "client_id": {CLIClientID}, "device_code": {d.DeviceCode}}, k)
}

func (h *harness) approve(l authtest.Login, code, decision string) resp {
	h.tb.Helper()
	return h.browser(l, "POST", "/api/auth/device/approve", map[string]string{"user_code": code, "decision": decision})
}

// tokens is a successful token response.
type tokens struct {
	Access, Refresh, Scope string
	ExpiresIn              int
	Raw                    resp
}

func tokensOf(tb testing.TB, r resp) tokens {
	tb.Helper()
	if r.Status != http.StatusOK {
		tb.Fatalf("token request: %d %s", r.Status, r.Raw)
	}
	e, _ := r.Body["expires_in"].(float64)
	return tokens{Access: r.str("access_token"), Refresh: r.str("refresh_token"), Scope: r.str("scope"), ExpiresIn: int(e), Raw: r}
}

// signInCLI runs the whole device flow for a fresh user of slug and returns
// the tokens, the key and the user's browser login.
func (h *harness) signInCLI(slug, email string, roles []auth.Role, c authtest.Ctx, k *ecdsa.PrivateKey) (tokens, authtest.Login) {
	h.tb.Helper()
	l := h.login(slug, email, roles, c)
	d := h.startDevice(slug, nil)
	if r := h.approve(l, d.UserCode, "approve"); r.Status != http.StatusOK {
		h.tb.Fatalf("approve: %d %s", r.Status, r.Raw)
	}
	return tokensOf(h.tb, h.devicePoll(slug, d, k)), l
}

// whoamiReq calls /api/whoami with an access token and a fresh proof.
func (h *harness) whoamiReq(k *ecdsa.PrivateKey, token string) resp {
	h.tb.Helper()
	target := h.srv.URL + "/api/whoami"
	return h.whoamiWith(token, "DPoP", map[string]string{"DPoP": h.proof(k, "GET", target, token, "")})
}

func (h *harness) whoamiWith(token, scheme string, hdr map[string]string) resp {
	h.tb.Helper()
	req, err := http.NewRequest(http.MethodGet, h.url("/api/whoami"), nil)
	if err != nil {
		h.tb.Fatal(err)
	}
	req.Header.Set("Authorization", scheme+" "+token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return do(h.tb, req)
}

// auditEvents lists a tenant's audit events with the action, oldest first.
func (h *harness) auditEvents(slug, action string) []*store.AuditEvent {
	h.tb.Helper()
	var out []*store.AuditEvent
	err := h.db.ReadTenant(context.Background(), h.tenantID(slug), func(tx *store.TenantTx) error {
		all, err := tx.AuditEventsRange(1, 0, 0)
		for _, e := range all {
			if e.Action == action {
				out = append(out, e)
			}
		}
		return err
	})
	if err != nil {
		h.tb.Fatal(err)
	}
	return out
}

// refreshRow reads a refresh token row by the hash it is stored under.
func (h *harness) refreshRow(slug, hash string) (rt *store.RefreshToken, err error) {
	h.tb.Helper()
	err = h.db.ReadTenant(context.Background(), h.tenantID(slug), func(tx *store.TenantTx) error {
		var err error
		rt, err = tx.RefreshTokenByHash(hash)
		return err
	})
	return rt, err
}

// mutateTenant runs fn in the tenant.
func (h *harness) mutateTenant(slug string, fn func(tx *store.TenantTx) error) {
	h.tb.Helper()
	if err := h.db.InTenant(context.Background(), h.tenantID(slug), fn); err != nil {
		h.tb.Fatal(err)
	}
}

func (h *harness) setSettings(slug, settings string) {
	h.tb.Helper()
	if err := h.db.InSystem(context.Background(), "test", func(s *store.SystemTx) error {
		return s.SetTenantSettings(h.tenantID(slug), settings)
	}); err != nil {
		h.tb.Fatal(err)
	}
}
