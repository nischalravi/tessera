package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// The OAuth routes through the real router (design §16.1, §19 PR10): the
// public allow-list, the audit trail, the step-up the approval route declares,
// and DPoP token principals meeting the permission, scope and CSRF rules.

const publicBase = "https://tessera.test"

// testClock is the server's clock; a test moves it.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type oauthEnv struct {
	t       *testing.T
	clock   *testClock
	f       *storetest.Fixture
	srv     *Server
	h       http.Handler
	sealer  *seal.Sealer
	slugA   string
	tenants map[string]tenancy.ID
}

func newOAuthEnv(t *testing.T) *oauthEnv {
	t.Helper()
	f := storetest.TwoTenants(t)
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	sealer, err := seal.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := keys.EnsureAll(ctx, f.DB, sealer, storetest.Now); err != nil {
		t.Fatal(err)
	}
	if err := oauth.EnsureCLIClients(ctx, f.DB, storetest.Now); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{t: storetest.Now}
	srv := New(Config{Store: f.DB, Clock: timeutil.Clock(clock.Now), Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{authtest.Origin}, Env: "test",
		RateLimits: noRateLimits, PublicURL: publicBase, Sealer: sealer})
	return &oauthEnv{t: t, clock: clock, f: f, srv: srv, h: srv.Handler(), sealer: sealer,
		tenants: map[string]tenancy.ID{"tenant-a": f.A.ID, "tenant-b": f.B.ID}}
}

func (e *oauthEnv) form(slug, endpoint string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/t/"+slug+"/oauth/"+endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return serve(e.h, req)
}

func body(rec *httptest.ResponseRecorder) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return m
}

// proof is a DPoP proof issued at the environment's current time.
func (e *oauthEnv) proof(k *ecdsa.PrivateKey, method, target, accessToken, nonce string) string {
	t := e.t
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]any{"jti": seal.RandomSecret(16), "htm": method, "htu": target, "iat": e.clock.Now().Unix()}
	if accessToken != "" {
		c["ath"] = dpop.AccessTokenHash(accessToken)
	}
	if nonce != "" {
		c["nonce"] = nonce
	}
	s, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// tokenRequest does the token endpoint's nonce dance and returns the response.
func (e *oauthEnv) tokenRequest(slug string, form url.Values, k *ecdsa.PrivateKey) *httptest.ResponseRecorder {
	e.t.Helper()
	target := publicBase + "/t/" + slug + "/oauth/token"
	first := e.form(slug, "token", form, map[string]string{"DPoP": e.proof(k, "POST", target, "", "")})
	nonce := first.Header().Get("DPoP-Nonce")
	if nonce == "" {
		e.t.Fatalf("no DPoP-Nonce: %d %s", first.Code, first.Body)
	}
	return e.form(slug, "token", form, map[string]string{"DPoP": e.proof(k, "POST", target, "", nonce)})
}

type cliTokens struct {
	access, refresh string
	key             *ecdsa.PrivateKey
	login           authtest.Login
	userCode        string
	deviceCode      string
}

// startDevice requests a device authorization.
func (e *oauthEnv) startDevice(slug, scope string) (device, user string) {
	e.t.Helper()
	rec := e.form(slug, "device_authorization", url.Values{"client_id": {oauth.CLIClientID}, "scope": {scope}}, nil)
	if rec.Code != 200 {
		e.t.Fatalf("device_authorization: %d %s", rec.Code, rec.Body)
	}
	b := body(rec)
	return b["device_code"].(string), b["user_code"].(string)
}

func (e *oauthEnv) approveVia(l authtest.Login, userCode string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/approve",
		strings.NewReader(`{"user_code":"`+userCode+`","decision":"approve"}`))
	req.Header.Set("Content-Type", "application/json")
	l.Apply(req)
	return serve(e.h, req)
}

// signInCLI runs the device flow for a user of slug.
func (e *oauthEnv) signInCLI(slug, email, scope string, roles []auth.Role, ctx ...authtest.Ctx) cliTokens {
	e.t.Helper()
	c := authtest.Phr
	if len(ctx) > 0 {
		c = ctx[0]
	}
	l := signIn(e.t, e.f.DB, e.tenants[slug], authtest.User{Email: email, Roles: roles}, c, storetest.Now)
	device, user := e.startDevice(slug, scope)
	if rec := e.approveVia(l, user); rec.Code != 200 {
		e.t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	rec := e.tokenRequest(slug, url.Values{"grant_type": {oauth.GrantDeviceCode}, "client_id": {oauth.CLIClientID},
		"device_code": {device}}, k)
	if rec.Code != 200 {
		e.t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
	b := body(rec)
	return cliTokens{access: b["access_token"].(string), refresh: b["refresh_token"].(string), key: k, login: l,
		userCode: user, deviceCode: device}
}

// call makes an API request as a token principal.
func (e *oauthEnv) call(c cliTokens, method, path, jsonBody string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	if jsonBody != "" {
		rd = strings.NewReader(jsonBody)
	}
	req := httptest.NewRequest(method, path, rd)
	if jsonBody != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "DPoP "+c.access)
	req.Header.Set("DPoP", e.proof(c.key, method, publicBase+strings.SplitN(path, "?", 2)[0], c.access, ""))
	for _, m := range mutate {
		m(req)
	}
	return serve(e.h, req)
}

// TestOAuth_DeviceFlowThroughRouter: the approval route declares STEP_UP_ADMIN,
// a token principal is authorized by role and scope, and nothing is lost to
// CSRF protection that does not apply to it.
func TestOAuth_DeviceFlowThroughRouter(t *testing.T) {
	e := newOAuthEnv(t)

	t.Run("the approval route needs a sign-in within 300 s", func(t *testing.T) {
		stale := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "old@b.example", Roles: []auth.Role{auth.RoleViewer}},
			authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-6 * time.Minute)}, storetest.Now)
		_, user := e.startDevice("tenant-b", "tessera:read")
		rec := e.approveVia(stale, user)
		b := body(rec)
		if rec.Code != 401 || b["error"] != "step_up_required" || b["max_age"] != float64(300) || b["acr"] != string(auth.ACRPhr) ||
			!strings.Contains(rec.Header().Get("WWW-Authenticate"), "insufficient_user_authentication") {
			t.Errorf("stale sign-in: %d %s %q", rec.Code, rec.Body, rec.Header().Get("WWW-Authenticate"))
		}
		weak := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "weak@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.AAL2, storetest.Now)
		if rec := e.approveVia(weak, user); rec.Code != 401 || body(rec)["error"] != "step_up_required" {
			t.Errorf("a sign-in without phishing resistance: %d %s", rec.Code, rec.Body)
		}
		fresh := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "fresh@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
		if rec := e.approveVia(fresh, user); rec.Code != 200 {
			t.Errorf("fresh sign-in: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("the approval needs CSRF protection like any session write", func(t *testing.T) {
		l := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "csrf@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
		_, user := e.startDevice("tenant-b", "tessera:read")
		req := httptest.NewRequest(http.MethodPost, "/api/auth/device/approve", strings.NewReader(`{"user_code":"`+user+`","decision":"approve"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(l.Cookie)
		req.Header.Set("Origin", authtest.Origin)
		if rec := serve(e.h, req); rec.Code != 403 || body(rec)["error"] != "csrf_failed" {
			t.Errorf("without the CSRF token: %d %s", rec.Code, rec.Body)
		}
		req = httptest.NewRequest(http.MethodPost, "/api/auth/device/approve", strings.NewReader(`{"user_code":"`+user+`","decision":"approve"}`))
		req.Header.Set("Content-Type", "application/json")
		l.Apply(req)
		req.Header.Set("Origin", "https://evil.example")
		if rec := serve(e.h, req); rec.Code != 403 {
			t.Errorf("from another origin: %d %s", rec.Code, rec.Body)
		}
	})

	op := []auth.Role{auth.RoleOperator}
	rw := e.signInCLI("tenant-b", "ops@b.example", "tessera:read tessera:write", op,
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-299 * time.Second)})
	ro := e.signInCLI("tenant-b", "reader@b.example", "tessera:read", op)

	t.Run("a token principal reads", func(t *testing.T) {
		rec := e.call(rw, "GET", "/api/summary", "")
		if rec.Code != 200 || leaks(rec.Body.String()) {
			t.Errorf("%d %.200s", rec.Code, rec.Body)
		}
		if rec := e.call(rw, "GET", "/api/auth/session", ""); rec.Code != 200 {
			t.Errorf("session: %d %s", rec.Code, rec.Body)
		} else if b := body(rec); b["csrf_token"] != "" || b["tenant"].(map[string]any)["slug"] != "tenant-b" {
			t.Errorf("session body: %s", rec.Body)
		}
	})
	t.Run("writes need no CSRF token but a write scope", func(t *testing.T) {
		rec := e.call(rw, "POST", "/api/jit/requests", `{"identity_id":1,"group_id":1,"justification":"x"}`)
		if rec.Code == 401 || rec.Code == 403 {
			t.Errorf("a write with a write scope and the operator role: %d %s", rec.Code, rec.Body)
		}
		rec = e.call(ro, "POST", "/api/jit/requests", `{"identity_id":1,"group_id":1,"justification":"x"}`)
		if rec.Code != 403 || body(rec)["error"] != "forbidden" || body(rec)["permission"] != "jit.request" {
			t.Errorf("a write with a read-only token: %d %s", rec.Code, rec.Body)
		}
		// roles still apply: an operator may not sweep, whatever the scope
		if rec := e.call(rw, "POST", "/api/jit/sweep", `{}`); rec.Code != 403 {
			t.Errorf("sweep by an operator: %d %s", rec.Code, rec.Body)
		}
		// a body must still be JSON
		if rec := e.call(rw, "POST", "/api/jit/requests", `x=1`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }); rec.Code != 415 {
			t.Errorf("a non-JSON body: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("an unauthenticated or malformed credential is 401 login_required with a challenge", func(t *testing.T) {
		for name, mutate := range map[string]func(*http.Request){
			"no proof": func(r *http.Request) { r.Header.Del("DPoP") },
			"Bearer":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+rw.access) },
			"proof of another key": func(r *http.Request) {
				r.Header.Set("DPoP", e.proof(ro.key, "GET", publicBase+"/api/summary", rw.access, ""))
			},
			"wrong method": func(r *http.Request) {
				r.Header.Set("DPoP", e.proof(rw.key, "POST", publicBase+"/api/summary", rw.access, ""))
			},
		} {
			rec := e.call(rw, "GET", "/api/summary", "", mutate)
			if rec.Code != 401 || body(rec)["error"] != "login_required" || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "DPoP ") {
				t.Errorf("%s: %d %s %q", name, rec.Code, rec.Body, rec.Header().Get("WWW-Authenticate"))
			}
		}
	})
	t.Run("calls are audited as the user through the CLI client", func(t *testing.T) {
		var found *store.AuditEvent
		for _, ev := range httpEvents(ledger(t, e.f.DB, e.f.B.ID)) {
			if strings.Contains(string(ev.HTTP), `"/api/summary"`) && ev.Outcome == store.OutcomeSuccess {
				found = ev
				break
			}
		}
		if found == nil || found.ActorType != store.ActorUser || found.ClientID == nil || *found.ClientID != oauth.CLIClientID ||
			found.SessionID == nil || len(found.Authn) == 0 {
			t.Fatalf("summary event: %+v", found)
		}
		if strings.Contains(string(found.Detail), rw.access) || strings.Contains(string(found.HTTP), "DPoP") {
			t.Error("the event records a credential")
		}
		// the token endpoint's own requests are tenant B's, by the CLI client
		for _, ev := range httpEvents(ledger(t, e.f.DB, e.f.B.ID)) {
			if strings.Contains(string(ev.HTTP), "/t/{slug}/oauth/token") && ev.ActorType == store.ActorAPIClient {
				return
			}
		}
		t.Error("no http.request event of the token endpoint by the api_client actor in tenant B's chain")
	})
	t.Run("a token principal cannot start a browser step-up or approve a device", func(t *testing.T) {
		rec := e.call(rw, "GET", "/api/auth/step-up?acr=urn:tessera:acr:phr&max_age=300&return_to=/", "")
		if rec.Code != 403 || body(rec)["error"] != "interactive_authentication_required" || rec.Header().Get("Set-Cookie") != "" {
			t.Errorf("step-up: %d %s", rec.Code, rec.Body)
		}
		_, user := e.startDevice("tenant-b", "tessera:read")
		rec = e.call(rw, "POST", "/api/auth/device/approve", `{"user_code":"`+user+`","decision":"approve"}`)
		if rec.Code != 403 || body(rec)["error"] != "interactive_authentication_required" {
			t.Errorf("approval by a CLI session: %d %s", rec.Code, rec.Body)
		}
	})
	// last: it moves the clock
	t.Run("a step-up route asks a CLI session with an old sign-in to sign in again, with the DPoP scheme", func(t *testing.T) {
		// rw's device was approved on a sign-in 299 s old; STEP_UP_POLICY allows 900 s
		if rec := e.call(rw, "POST", "/api/jit/requests/1/approve", `{}`); rec.Code == 401 {
			t.Fatalf("asked for a step-up too early: %s", rec.Body)
		}
		// 620 s later the sign-in is 919 s old; the access token expired 20 s ago, inside its 30 s leeway
		e.clock.Advance(620 * time.Second)
		rec := e.call(rw, "POST", "/api/jit/requests/1/approve", `{}`)
		b := body(rec)
		ch := rec.Header().Get("WWW-Authenticate")
		if rec.Code != 401 || b["error"] != "step_up_required" || b["max_age"] != float64(900) || b["acr"] != string(auth.ACRPhr) ||
			!strings.HasPrefix(ch, `DPoP error="insufficient_user_authentication"`) || !strings.Contains(ch, `max_age=900`) ||
			!strings.Contains(ch, `acr_values="urn:tessera:acr:phr"`) {
			t.Errorf("%d %s %q", rec.Code, rec.Body, ch)
		}
		// reads are not step-up routes
		if rec := e.call(rw, "GET", "/api/summary", ""); rec.Code != 200 {
			t.Errorf("a read: %d %s", rec.Code, rec.Body)
		}
	})
}

// TestOAuth_CrossTenant: one tenant's device codes, user codes and refresh
// tokens mean nothing at another tenant's endpoints, and a token's tenant is
// its issuer's.
func TestOAuth_CrossTenant(t *testing.T) {
	e := newOAuthEnv(t)
	op := []auth.Role{auth.RoleOperator}
	a := e.signInCLI("tenant-a", "ops@a.example", "tessera:read", op)

	// A's refresh token at B
	rec := e.tokenRequest("tenant-b", url.Values{"grant_type": {oauth.GrantRefresh}, "client_id": {oauth.CLIClientID},
		"refresh_token": {a.refresh}}, a.key)
	if rec.Code != 400 || body(rec)["error"] != "invalid_grant" {
		t.Errorf("A's refresh token at B: %d %s", rec.Code, rec.Body)
	}
	// B answers exactly like a refresh token that never existed
	missing := e.tokenRequest("tenant-b", url.Values{"grant_type": {oauth.GrantRefresh}, "client_id": {oauth.CLIClientID},
		"refresh_token": {"trt_" + seal.RandomSecret(32)}}, a.key)
	if rec.Code != missing.Code || rec.Body.String() != missing.Body.String() {
		t.Errorf("A's token is distinguishable from a missing one:\n%d %s\n%d %s", rec.Code, rec.Body, missing.Code, missing.Body)
	}
	// and A's token is untouched
	if rec := e.tokenRequest("tenant-a", url.Values{"grant_type": {oauth.GrantRefresh}, "client_id": {oauth.CLIClientID},
		"refresh_token": {a.refresh}}, a.key); rec.Code != 200 {
		t.Errorf("A's token after the attempt: %d %s", rec.Code, rec.Body)
	}

	// A's device code and user code at B
	device, user := e.startDevice("tenant-a", "tessera:read")
	if rec := e.tokenRequest("tenant-b", url.Values{"grant_type": {oauth.GrantDeviceCode}, "client_id": {oauth.CLIClientID},
		"device_code": {device}}, a.key); rec.Code != 400 || body(rec)["error"] != "invalid_grant" {
		t.Errorf("A's device code at B: %d %s", rec.Code, rec.Body)
	}
	bl := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "ops@b.example", Roles: op}, authtest.Phr, storetest.Now)
	if rec := e.approveVia(bl, user); rec.Code != 404 {
		t.Errorf("B's user approving A's code: %d %s", rec.Code, rec.Body)
	}
	lookup := httptest.NewRequest(http.MethodPost, "/api/auth/device/lookup", strings.NewReader(`{"user_code":"`+user+`"}`))
	lookup.Header.Set("Content-Type", "application/json")
	bl.Apply(lookup)
	if rec := serve(e.h, lookup); rec.Code != 404 || strings.Contains(rec.Body.String(), "request_ip") {
		t.Errorf("B's user looking up A's code: %d %s", rec.Code, rec.Body)
	}
	// A's grant is still pending for A
	al := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "ops@a.example", Roles: op}, authtest.Phr, storetest.Now)
	if rec := e.approveVia(al, user); rec.Code != 200 {
		t.Errorf("A's own approval after the attempts: %d %s", rec.Code, rec.Body)
	}

	// A's token is A's: the principal is tenant A's, whichever tenant the caller meant
	rec = e.call(a, "GET", "/api/auth/session", "")
	if tenant := body(rec)["tenant"].(map[string]any)["slug"]; rec.Code != 200 || tenant != "tenant-a" {
		t.Errorf("A's token: %d %s", rec.Code, rec.Body)
	}
	// metadata and keys are per tenant
	for slug, tid := range map[string]tenancy.ID{"tenant-a": e.f.A.ID, "tenant-b": e.f.B.ID} {
		rec := serve(e.h, httptest.NewRequest(http.MethodGet, "/t/"+slug+"/.well-known/jwks.json", nil))
		var set struct{ Keys []struct{ Kid string } }
		_ = json.Unmarshal(rec.Body.Bytes(), &set)
		var want []string
		_ = e.f.DB.ReadTenant(context.Background(), tid, func(tx *store.TenantTx) error {
			ks, err := keys.PublishedKeys(tx, store.KeyPurposeAccessToken, storetest.Now)
			for _, k := range ks {
				want = append(want, k.KID)
			}
			return err
		})
		if rec.Code != 200 || len(set.Keys) != len(want) || len(want) == 0 {
			t.Fatalf("%s JWKS: %d %s", slug, rec.Code, rec.Body)
		}
		for i, k := range set.Keys {
			if k.Kid != want[i] || !strings.Contains(k.Kid, slug) {
				t.Errorf("%s JWKS has key %s, want %s", slug, k.Kid, want[i])
			}
		}
	}
}

// TestOAuth_WellKnownNotAudited: the well-known documents carry no tenant
// data and, like /api/health, write no http.request event (§13.4).
func TestOAuth_WellKnownNotAudited(t *testing.T) {
	e := newOAuthEnv(t)
	count := func() int {
		return len(ledger(t, e.f.DB, e.f.A.ID)) + len(ledger(t, e.f.DB, e.f.B.ID)) + len(ledger(t, e.f.DB, tenancy.Platform))
	}
	before := count()
	for _, p := range []string{"/t/tenant-a/.well-known/oauth-authorization-server", "/t/tenant-a/.well-known/jwks.json",
		"/.well-known/oauth-protected-resource", "/t/nobody/.well-known/jwks.json"} {
		rec := serve(e.h, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != 200 && rec.Code != 404 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if got := count(); got != before {
		t.Errorf("the well-known documents wrote %d events", got-before)
	}
	// the documents are public: no session needed, no cookie set
	rec := serve(e.h, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if rec.Code != 200 || len(rec.Result().Cookies()) != 0 || !strings.Contains(rec.Body.String(), publicBase+"/api") {
		t.Errorf("protected resource metadata: %d %s", rec.Code, rec.Body)
	}
}

// TestOAuth_PublicRoutesAudited: a call to a public OAuth route writes one
// http.request event on the chain of the tenant whose endpoint it is; an
// unknown tenant's is recorded on the platform chain.
func TestOAuth_PublicRoutesAudited(t *testing.T) {
	e := newOAuthEnv(t)
	count := func(tn tenancy.ID) int { return len(httpEvents(ledger(t, e.f.DB, tn))) }
	a, b, p := count(e.f.A.ID), count(e.f.B.ID), count(tenancy.Platform)
	rec := e.form("tenant-a", "device_authorization", url.Values{"client_id": {oauth.CLIClientID}}, nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if count(e.f.A.ID) != a+1 || count(e.f.B.ID) != b || count(tenancy.Platform) != p {
		t.Errorf("events: A +%d, B +%d, platform +%d", count(e.f.A.ID)-a, count(e.f.B.ID)-b, count(tenancy.Platform)-p)
	}
	ev := httpEvents(ledger(t, e.f.DB, e.f.A.ID))[0]
	if ev.ActorType != store.ActorAnonymous || !strings.Contains(string(ev.HTTP), "/t/{slug}/oauth/device_authorization") ||
		strings.Contains(string(ev.HTTP), "tenant-a") && !strings.Contains(string(ev.HTTP), `"slug":"tenant-a"`) {
		t.Errorf("event: %s %s", ev.ActorType, ev.HTTP)
	}
	a, p = count(e.f.A.ID), count(tenancy.Platform)
	if rec := e.form("nobody", "token", url.Values{"grant_type": {oauth.GrantRefresh}}, nil); rec.Code != 404 {
		t.Fatalf("unknown tenant: %d", rec.Code)
	}
	if count(tenancy.Platform) != p+1 || count(e.f.A.ID) != a {
		t.Errorf("an unknown tenant's call: platform +%d, A +%d", count(tenancy.Platform)-p, count(e.f.A.ID)-a)
	}
}

// TestOAuth_RoutesDeclared: the session routes of the device flow declare what
// the design says; the public ones are exactly the allow-listed OAuth routes.
func TestOAuth_RoutesDeclared(t *testing.T) {
	e := newOAuthEnv(t)
	got := map[string]RouteInfo{}
	for _, rt := range e.srv.Routes() {
		got[rt.Method+" "+rt.Pattern] = rt
	}
	lookup, approve := got["POST /api/auth/device/lookup"], got["POST /api/auth/device/approve"]
	if lookup.Public || lookup.Perm != auth.PermAuthenticated || lookup.Authn != nil {
		t.Errorf("lookup: %+v", lookup)
	}
	if approve.Public || approve.Perm != auth.PermAuthenticated || approve.Authn == nil || *approve.Authn != auth.StepUpAdmin {
		t.Errorf("approve: %+v", approve)
	}
	for _, k := range []string{"GET /t/{slug}/.well-known/oauth-authorization-server", "GET /t/{slug}/.well-known/jwks.json",
		"GET /.well-known/oauth-protected-resource", "POST /t/{slug}/oauth/device_authorization", "POST /t/{slug}/oauth/token",
		"POST /t/{slug}/oauth/revoke", "POST /t/{slug}/oauth/introspect"} {
		if rt, ok := got[k]; !ok || !rt.Public || rt.Tenant {
			t.Errorf("%s: %+v (public, and it opens its own transactions)", k, rt)
		}
	}
}
