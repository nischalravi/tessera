package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body.String(), err)
	}
	return v
}

func authed(l authtest.Login, method, path, body string) *http.Request {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	l.Apply(r)
	return r
}

// TestAuthSession: GET /api/auth/session describes the principal: user,
// tenant (from the session), assigned/active/inactive roles, permissions,
// the authentication summary, the session's expiry and the CSRF token.
func TestAuthSession(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	weak := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ada@b.example", Display: "Ada",
		Roles: []auth.Role{auth.RoleTenantAdmin, auth.RoleOperator}}, authtest.AAL2, storetest.Now)
	v := decode(t, serve(h, authed(weak, "GET", "/api/auth/session", "")))
	if at(v, "user", "email") != "ada@b.example" || at(v, "tenant", "slug") != f.B.Slug || at(v, "csrf_token") != weak.CSRFToken {
		t.Errorf("session %v", v)
	}
	if roles := at(v, "active_roles").([]any); len(roles) != 1 || roles[0] != "operator" {
		t.Errorf("active roles %v", roles)
	}
	if inactive := at(v, "inactive_roles").([]any); len(inactive) != 1 || at(inactive[0], "role") != "tenant_admin" ||
		at(inactive[0], "reason") != auth.InactiveNeedsPhr {
		t.Errorf("inactive roles %v", inactive)
	}
	if at(v, "authn", "phishing_resistant") != false || at(v, "authn", "aal") != 2.0 || at(v, "authn", "acr") != string(auth.ACRAAL2) {
		t.Errorf("authn %v", at(v, "authn"))
	}
	perms, _ := json.Marshal(at(v, "permissions"))
	if strings.Contains(string(perms), "audit.read") || !strings.Contains(string(perms), "jit.request") {
		t.Errorf("permissions %s", perms)
	}
	if s := at(v, "session", "idle_expires_at"); s != "2026-10-08T10:30:00Z" {
		t.Errorf("idle expiry %v", s)
	}
	for _, secret := range []string{weak.Cookie.Value, auth.HashSecret(weak.Cookie.Value)} {
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), secret) {
			t.Error("the session secret or its hash is returned")
		}
	}
	if rec := serve(h, httptest.NewRequest("GET", "/api/auth/session", nil)); rec.Code != 401 {
		t.Errorf("anonymous session: %d", rec.Code)
	}
}

// TestAuthLogout: logout revokes the session, clears the cookie, is audited,
// and the old cookie no longer works.
func TestAuthLogout(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	l := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	// logout is a state change: it needs the CSRF token
	noCSRF := authed(l, "POST", "/api/auth/logout", "")
	noCSRF.Header.Del(auth.CSRFHeader)
	if rec := serve(h, noCSRF); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "csrf_failed") {
		t.Errorf("logout without CSRF: %d %s", rec.Code, rec.Body.String())
	}
	rec := serve(h, authed(l, "POST", "/api/auth/logout", ""))
	if rec.Code != 200 {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body.String())
	}
	if c := rec.Header().Get("Set-Cookie"); !strings.Contains(c, auth.CookieName+"=;") || !strings.Contains(c, "Max-Age=0") {
		t.Errorf("logout cookie %q", c)
	}
	if rec := serve(h, authed(l, "GET", "/api/summary", "")); rec.Code != 401 {
		t.Errorf("after logout: %d", rec.Code)
	}
	found := false
	for _, e := range ledger(t, f.DB, f.B.ID) {
		if e.Action == "auth.logout" && e.SessionID != nil && *e.SessionID == l.SessionID.String() {
			found = true
		}
	}
	if !found {
		t.Error("no auth.logout event")
	}
}

// TestAuthSessionsAndRevoke: a user lists and revokes their own sessions;
// another user's session is 404 without admin.sessions.revoke, and an admin
// may revoke it; another tenant's session is always 404.
func TestAuthSessionsAndRevoke(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	vic := authtest.User{Email: "vic@b.example", Roles: []auth.Role{auth.RoleViewer}}
	v1 := signIn(t, f.DB, f.B.ID, vic, authtest.Phr, storetest.Now)
	v2 := signIn(t, f.DB, f.B.ID, vic, authtest.Phr, storetest.Now)
	olu := signIn(t, f.DB, f.B.ID, authtest.User{Email: "olu@b.example", Roles: []auth.Role{auth.RoleOperator}},
		authtest.Phr, storetest.Now)
	adminB := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	adminA := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)

	var list []map[string]any
	if err := json.Unmarshal(serve(h, authed(v1, "GET", "/api/auth/sessions", "")).Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("vic sees %d sessions, want her 2", len(list))
	}
	// olu cannot revoke vic's session: indistinguishable from a missing one
	if rec := serve(h, authed(olu, "DELETE", "/api/auth/sessions/"+v2.SessionID.String(), "")); rec.Code != 404 {
		t.Errorf("revoking another user's session without the permission: %d", rec.Code)
	}
	// an admin of another tenant cannot either
	if rec := serve(h, authed(adminA, "DELETE", "/api/auth/sessions/"+v2.SessionID.String(), "")); rec.Code != 404 {
		t.Errorf("revoking another tenant's session: %d", rec.Code)
	}
	if rec := serve(h, authed(v2, "GET", "/api/summary", "")); rec.Code != 200 {
		t.Fatalf("the session was revoked by an unauthorized caller: %d", rec.Code)
	}
	// vic revokes her other session
	if rec := serve(h, authed(v1, "DELETE", "/api/auth/sessions/"+v2.SessionID.String(), "")); rec.Code != 200 {
		t.Fatalf("own revoke: %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(h, authed(v2, "GET", "/api/summary", "")); rec.Code != 401 {
		t.Errorf("revoked session still works: %d", rec.Code)
	}
	if rec := serve(h, authed(v1, "DELETE", "/api/auth/sessions/"+v2.SessionID.String(), "")); rec.Code != 409 {
		t.Errorf("revoking twice: %d", rec.Code)
	}
	// the tenant admin revokes olu's session (admin.sessions.revoke)
	if rec := serve(h, authed(adminB, "DELETE", "/api/auth/sessions/"+olu.SessionID.String(), "")); rec.Code != 200 {
		t.Fatalf("admin revoke: %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(h, authed(olu, "GET", "/api/summary", "")); rec.Code != 401 {
		t.Errorf("admin-revoked session still works: %d", rec.Code)
	}
	if rec := serve(h, authed(v1, "DELETE", "/api/auth/sessions/not-a-uuid", "")); rec.Code != 404 {
		t.Errorf("bad id: %d", rec.Code)
	}
}

// TestUnsafeRequestsNeedCSRFAndJSON: on every unsafe route a session's
// request without the CSRF token, from a foreign origin, or with a non-JSON
// body is refused before the handler runs.
func TestUnsafeRequestsNeedCSRFAndJSON(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	l := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	before := domainEvents(ledger(t, f.DB, f.B.ID))
	for _, rt := range srv.Routes() {
		if auth.SafeMethod(rt.Method) || rt.Public {
			continue
		}
		for name, mutate := range map[string]func(*http.Request){
			"no token":       func(r *http.Request) { r.Header.Del(auth.CSRFHeader) },
			"wrong token":    func(r *http.Request) { r.Header.Set(auth.CSRFHeader, "forged") },
			"foreign origin": func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
			"no origin":      func(r *http.Request) { r.Header.Del("Origin") },
		} {
			req := routeRequest(rt, f.B)
			l.Apply(req)
			mutate(req)
			if rec := serve(h, req); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "csrf_failed") {
				t.Errorf("%s %s (%s): %d %.120s, want 403 csrf_failed", rt.Method, rt.Pattern, name, rec.Code, rec.Body.String())
			}
		}
		req := routeRequest(rt, f.B)
		l.Apply(req)
		req.Body = io.NopCloser(strings.NewReader("edge_id=1"))
		req.ContentLength = 9
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if rec := serve(h, req); rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%s %s with a form body: %d, want 415", rt.Method, rt.Pattern, rec.Code)
		}
	}
	// nothing ran: no domain event was written (only the refused requests'
	// http.request events)
	if got := domainEvents(ledger(t, f.DB, f.B.ID)); got != before {
		t.Errorf("refused requests wrote %d domain events", got-before)
	}
}

func domainEvents(evs []*store.AuditEvent) int {
	n := 0
	for _, e := range evs {
		if e.Action != store.ActionHTTPRequest {
			n++
		}
	}
	return n
}

// TestSecurityHeaders (design §5.2, §20.4 headers_test): CSP and
// frame-ancestors, nosniff, no-referrer, no-store on API responses, HSTS in
// production, CORS with credentials only for configured origins.
func TestSecurityHeaders(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	l := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	for _, path := range []string{"/api/summary", "/api/auth/session", "/api/health", "/docs", "/api/nope"} {
		rec := serve(h, authed(l, "GET", path, ""))
		hd := rec.Header()
		csp := hd.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || hd.Get("X-Content-Type-Options") != "nosniff" ||
			hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: headers %v", path, hd)
		}
		if strings.HasPrefix(path, "/api/") && hd.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", path, hd.Get("Cache-Control"))
		}
		if path != "/docs" && !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("%s: CSP %q", path, csp)
		}
		if hd.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS outside production", path)
		}
	}
	prod := New(Config{Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS), HSTS: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler()
	if rec := serve(prod, httptest.NewRequest("GET", "/api/health", nil)); !strings.Contains(rec.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Error("no HSTS in production")
	}
	// CORS: the configured origin gets credentials; another origin nothing
	pre := httptest.NewRequest("OPTIONS", "/api/jit/sweep", nil)
	pre.Header.Set("Origin", "http://localhost:5173")
	pre.Header.Set("Access-Control-Request-Method", "POST")
	pre.Header.Set("Access-Control-Request-Headers", "content-type,x-tessera-csrf")
	rec := serve(h, pre)
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" ||
		rec.Header().Get("Access-Control-Allow-Credentials") != "true" ||
		!strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), auth.CSRFHeader) {
		t.Errorf("preflight: %v", rec.Header())
	}
	pre.Header.Set("Origin", "https://evil.example")
	if rec := serve(h, pre); rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Code != 400 {
		t.Errorf("foreign preflight: %d %v", rec.Code, rec.Header())
	}
}

// devLoginServer is a dev-environment server over a seed with the dev IdP
// connection and its bootstrap users.
func devLoginServer(t *testing.T, env string) (*Server, *store.DB) {
	t.Helper()
	return devLoginServerOpt(t, env, false)
}

// devLoginServerOpt is devLoginServer with TESSERA_DEV_LOGIN.
func devLoginServerOpt(t *testing.T, env string, optIn bool) (*Server, *store.DB) {
	t.Helper()
	db := testkit.Open(t)
	conns := []connectors.Connector{connectors.Tiny{Now: testkit.Now}}
	tenants := seed.WithDevIdP([]seed.Tenant{
		{ID: seed.LarkspurID, Slug: seed.LarkspurSlug, Name: "Larkspur Labs", Connectors: conns},
		{ID: seed.GlobexID, Slug: seed.GlobexSlug, Name: "Globex", Connectors: []connectors.Connector{connectors.Tiny{Now: testkit.Now, Sentinel: "G"}}},
	}, "http://127.0.0.1:8001")
	if _, err := seed.Run(context.Background(), db, testkit.Now, testkit.Policies(t), tenants); err != nil {
		t.Fatal(err)
	}
	return New(Config{Store: db, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS), Env: env,
		DevLogin: optIn, AllowedOrigins: []string{authtest.Origin}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}), db
}

func devLogin(h http.Handler, body, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/auth/dev-login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return serve(h, r)
}

// sessionCookie extracts the session cookie a response set.
func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie in %v", rec.Header())
	return nil
}

// TestDevLogin (§19 PR5, guarded by §18.4): dev sign-in resolves the user
// through the dev_mock connection's (connection, subject) link, normalizes
// the chosen method like an Okta login that asked for phr, and is audited.
func TestDevLogin(t *testing.T) {
	srv, db := devLoginServer(t, "dev")
	h := srv.Handler()
	// the picker lists the seeded users of the named tenant only
	for q, want := range map[string]int{"?tenant=larkspur": len(seed.LarkspurUsers), "?tenant=globex": len(seed.GlobexUsers),
		"": 0, "?tenant=nope": 0, "?tenant=_platform": 0} {
		list := decode(t, serve(h, httptest.NewRequest("GET", "/api/auth/dev-login"+q, nil)))
		users := at(list, "users").([]any)
		if len(users) != want {
			t.Errorf("%q: %d dev users, want %d", q, len(users), want)
		}
		for _, u := range users {
			if slug := strings.TrimPrefix(q, "?tenant="); u.(map[string]any)["tenant"] != slug {
				t.Errorf("%q lists a user of another tenant: %v", q, u)
			}
		}
	}
	for _, tc := range []struct {
		subject, method string
		activeAdmin     bool
		acr             string
	}{
		{"00u-alice-admin", "passkey", true, string(auth.ACRPhr)},
		{"00u-alice-admin", "password_otp", false, string(auth.ACRAAL2)},
		{"00u-ivan-admin2", "hardware_key", true, string(auth.ACRPhr)},
		{"00u-alice-admin", "password", false, string(auth.ACRAAL1)},
	} {
		rec := devLogin(h, `{"tenant":"larkspur","subject":"`+tc.subject+`","method":"`+tc.method+`"}`, authtest.Origin)
		if rec.Code != 200 {
			t.Fatalf("%s %s: %d %s", tc.subject, tc.method, rec.Code, rec.Body.String())
		}
		c := sessionCookie(t, rec)
		req := httptest.NewRequest("GET", "/api/auth/session", nil)
		req.AddCookie(c)
		v := decode(t, serve(h, req))
		active, _ := json.Marshal(at(v, "active_roles"))
		if strings.Contains(string(active), "tenant_admin") != tc.activeAdmin || at(v, "authn", "acr") != tc.acr ||
			at(v, "tenant", "slug") != "larkspur" {
			t.Errorf("%s %s: active %s authn %v", tc.subject, tc.method, active, at(v, "authn"))
		}
	}
	// the dev-login session works like any other (Pat approves with a passkey)
	rec := devLogin(h, `{"tenant":"larkspur","subject":"00u-pat-policy","method":"passkey"}`, authtest.Origin)
	req := httptest.NewRequest("POST", "/api/jit/sweep", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", authtest.Origin)
	req.AddCookie(sessionCookie(t, rec))
	req.Header.Set(auth.CSRFHeader, decode(t, rec)["csrf_token"].(string))
	if r := serve(h, req); r.Code != 200 {
		t.Errorf("sweep as Pat: %d %s", r.Code, r.Body.String())
	}
	// refusals: generic 401, audited with the reason
	for body, reason := range map[string]string{
		`{"tenant":"larkspur","subject":"00u-gina-globex"}`:              "unknown_subject", // Gina belongs to globex
		`{"tenant":"larkspur","subject":"alice.admin@larkspur.example"}`: "unknown_subject", // never by email
		`{"tenant":"nope","subject":"00u-alice-admin"}`:                  "unknown_tenant",
		`{"tenant":"_platform","subject":"00u-alice-admin"}`:             "unknown_tenant",
	} {
		rec := devLogin(h, body, authtest.Origin)
		if rec.Code != 401 || !strings.Contains(rec.Body.String(), "login_failed") || len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
		chain := seed.LarkspurID
		if reason == "unknown_tenant" {
			chain = tenancy.Platform
		}
		var last *store.AuditEvent
		for _, e := range ledger(t, db, chain) {
			if e.Action == "auth.login.failure" {
				last = e
				break
			}
		}
		if last == nil || !strings.Contains(string(last.Detail), reason) || last.ActorType != store.ActorAnonymous {
			t.Errorf("%s: no auth.login.failure with reason %s: %+v", body, reason, last)
		}
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"foreign origin": devLogin(h, `{"tenant":"larkspur","subject":"00u-alice-admin"}`, "https://evil.example"),
		"no origin":      devLogin(h, `{"tenant":"larkspur","subject":"00u-alice-admin"}`, ""),
		"unknown field":  devLogin(h, `{"tenant":"larkspur","subject":"00u-alice-admin","roles":["tenant_admin"]}`, authtest.Origin),
		"unknown method": devLogin(h, `{"tenant":"larkspur","subject":"00u-alice-admin","method":"magic"}`, authtest.Origin),
	} {
		if rec.Code == 200 || len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	found := false
	for _, e := range ledger(t, db, seed.LarkspurID) {
		if e.Action == "auth.login.success" && e.ActorType == store.ActorUser && strings.Contains(string(e.Detail), `"via":"dev_login"`) {
			found = true
		}
	}
	if !found {
		t.Error("no auth.login.success event attributed to the user")
	}
}

// TestDevLoginOnlyInDevAndTest: with any other environment the routes do not
// exist.
func TestDevLoginOnlyInDevAndTest(t *testing.T) {
	for _, env := range []string{"", "prod"} {
		srv, _ := devLoginServer(t, env)
		h := srv.Handler()
		if rec := devLogin(h, `{"tenant":"larkspur","subject":"00u-alice-admin"}`, authtest.Origin); rec.Code != 404 {
			t.Errorf("TESSERA_ENV=%q: dev-login answered %d", env, rec.Code)
		}
		for _, rt := range srv.Routes() {
			if strings.Contains(rt.Pattern, "dev-login") {
				t.Errorf("TESSERA_ENV=%q registers %s %s", env, rt.Method, rt.Pattern)
			}
		}
	}
}

// TestDevLoginTestEnvNeedsOptInAndLoopback: with TESSERA_ENV=test the routes
// exist only with TESSERA_DEV_LOGIN, and then answer loopback peers only.
func TestDevLoginTestEnvNeedsOptInAndLoopback(t *testing.T) {
	body := `{"tenant":"larkspur","subject":"00u-alice-admin"}`
	srv, _ := devLoginServerOpt(t, "test", false)
	if rec := devLogin(srv.Handler(), body, authtest.Origin); rec.Code != 404 {
		t.Errorf("test without opt-in: %d", rec.Code)
	}
	for _, rt := range srv.Routes() {
		if strings.Contains(rt.Pattern, "dev-login") {
			t.Errorf("test without opt-in registers %s %s", rt.Method, rt.Pattern)
		}
	}
	srv, _ = devLoginServerOpt(t, "test", true)
	h := srv.Handler()
	for addr, ok := range map[string]bool{"127.0.0.1:5555": true, "[::1]:5555": true, "[::ffff:127.0.0.1]:5555": true,
		"192.0.2.1:1234": false, "10.0.0.7:80": false, "[2001:db8::1]:443": false, "garbage": false} {
		post := httptest.NewRequest("POST", "/api/auth/dev-login", strings.NewReader(body))
		post.Header.Set("Content-Type", "application/json")
		post.Header.Set("Origin", authtest.Origin)
		post.Header.Set("X-Forwarded-For", "127.0.0.1") // never trusted
		post.RemoteAddr = addr
		get := httptest.NewRequest("GET", "/api/auth/dev-login?tenant=larkspur", nil)
		get.RemoteAddr = addr
		pc, gc := serve(h, post).Code, serve(h, get).Code
		if ok && (pc != 200 || gc != 200) || !ok && (pc != 404 || gc != 404) {
			t.Errorf("%s: POST %d GET %d (allowed %v)", addr, pc, gc, ok)
		}
	}
}

// TestIsolation_SessionTenantOnly: a user of tenant A reaches only A's data,
// whatever tenant the request names; B's objects are not found.
func TestIsolation_SessionTenantOnly(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	la := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)
	lb := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	req := authed(lb, "GET", "/api/identities?tenant="+f.A.Slug+"&tenant_id="+f.A.ID.String(), "")
	req.Header.Set("X-Tessera-Tenant", f.A.ID.String())
	if rec := serve(h, req); rec.Code != 200 || leaks(rec.Body.String()) {
		t.Errorf("B's session naming tenant A: %d leaks=%t", rec.Code, leaks(rec.Body.String()))
	}
	if rec := serve(h, authed(la, "GET", "/api/identities", "")); !leaks(rec.Body.String()) {
		t.Error("A's own session does not see A's data (the test would prove nothing)")
	}
	if rec := serve(h, authed(lb, "GET", "/api/identities/"+fmt.Sprint(f.A.IDs["alice"]), "")); rec.Code != 404 {
		t.Errorf("B reading A's identity: %d", rec.Code)
	}
	// two session cookies: one session is used (the first), never a mix
	both := authed(lb, "GET", "/api/identities", "")
	both.AddCookie(la.Cookie)
	if rec := serve(h, both); rec.Code != 200 || leaks(rec.Body.String()) {
		t.Errorf("two cookies: %d leaks=%t", rec.Code, leaks(rec.Body.String()))
	}
}

// TestJITSelfApprovalRefused: the platform user who made a JIT request
// cannot approve it (403 self_approval, audited, nothing granted); another
// approver can.
func TestJITSelfApprovalRefused(t *testing.T) {
	srv := newSeededServer(t) // the demo company; Priya (33) may request BreakGlassAdmin (24)
	h := srv.Anonymous()
	// the requester holds jit.decide too (operator), so only the self check stops them
	rec := serve(h, authed(srv.requester, "POST", "/api/jit/requests", `{"identity_id":33,"group_id":24,"justification":"incident"}`))
	if rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	id := int(decode(t, rec)["id"].(float64))
	path := fmt.Sprintf("/api/jit/requests/%d/approve", id)
	rec = serve(h, authed(srv.requester, "POST", path, ""))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"self_approval"`) {
		t.Fatalf("self-approval: %d %s", rec.Code, rec.Body.String())
	}
	refused := false
	for _, e := range ledger(t, srv.store, seed.LarkspurID) {
		if e.Action == "jit.approve.refused" && strings.Contains(string(e.Detail), "self_approval") &&
			e.ActorID != nil && *e.ActorID == parityRequester.ID.String() {
			refused = true
		}
		if e.Action == "jit.approve" && strings.Contains(string(e.Detail), fmt.Sprintf(`"request_id":%d,`, id)) {
			t.Error("self-approval wrote jit.approve")
		}
	}
	if !refused {
		t.Error("no jit.approve.refused event attributed to the requester")
	}
	rec = serve(h, authed(srv.login, "POST", path, ""))
	if rec.Code != 200 || decode(t, rec)["status"] != "approved" {
		t.Fatalf("approval by another user: %d %s", rec.Code, rec.Body.String())
	}
}
