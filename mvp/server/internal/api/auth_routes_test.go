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
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

func decode(t testing.TB, rec *httptest.ResponseRecorder) map[string]any {
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// TestIsolation_SessionTenantOnly: a user of tenant A reaches only A's data,
// whatever tenant the request names; B's objects are not found.
func TestIsolation_SessionTenantOnly(t *testing.T) {
	t.Parallel()
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

// TestJITSelfApprovalRefused: neither the platform user who made a JIT
// request nor the one linked to the identity that would get the access can
// approve it (403 self_approval, audited, nothing granted); another approver
// can.
func TestJITSelfApprovalRefused(t *testing.T) {
	t.Parallel()
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
	// nor can the person who would get the access (Priya's own platform user)
	priyaID := int64(33)
	priya := signIn(t, srv.store, seed.LarkspurID, authtest.User{Email: "priya.ramaswamy@larkspur.example", Display: "Priya",
		Roles: []auth.Role{auth.RolePolicyAdmin}, IdentityID: &priyaID}, authtest.Phr, FrozenNow)
	if rec := serve(h, authed(priya, "POST", path, "")); rec.Code != 403 || !strings.Contains(rec.Body.String(), `"self_approval"`) {
		t.Fatalf("approval by the beneficiary: %d %s", rec.Code, rec.Body.String())
	}
	// nor a platform user with no linked identity: the check cannot prove they are someone else (#443)
	unlinked := signIn(t, srv.store, seed.LarkspurID, authtest.User{Email: "unlinked.approver@larkspur.example", Display: "Unlinked",
		Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, FrozenNow)
	if rec := serve(h, authed(unlinked, "POST", path, "")); rec.Code != 403 || !strings.Contains(rec.Body.String(), `"approver_unlinked"`) {
		t.Fatalf("approval by an unlinked user: %d %s", rec.Code, rec.Body.String())
	}
	refusedUnlinked := false
	for _, e := range ledger(t, srv.store, seed.LarkspurID) {
		if e.Action == "jit.approve.refused" && strings.Contains(string(e.Detail), "approver_unlinked") {
			refusedUnlinked = true
		}
	}
	if !refusedUnlinked {
		t.Error("no jit.approve.refused event for the unlinked approver")
	}
	rec = serve(h, authed(srv.login, "POST", path, ""))
	if rec.Code != 200 || decode(t, rec)["status"] != "approved" {
		t.Fatalf("approval by another user: %d %s", rec.Code, rec.Body.String())
	}
}

// TestTenantSettingsRaiseRoleFloor (§18.3): a tenant's require_phr_for_all
// is applied to its own sessions on every request: an operator signed in
// with AAL2 has an inactive role there, and is unaffected in another tenant.
func TestTenantSettingsRaiseRoleFloor(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	op := authtest.User{Email: "op@x.example", Display: "Op", Roles: []auth.Role{auth.RoleOperator}}
	la := signIn(t, f.DB, f.A.ID, op, authtest.AAL2, storetest.Now)
	lb := signIn(t, f.DB, f.B.ID, op, authtest.AAL2, storetest.Now)
	if err := f.DB.InSystem(context.Background(), "test settings", func(st *store.SystemTx) error {
		return st.SetTenantSettings(f.B.ID, `{"require_phr_for_all":true}`)
	}); err != nil {
		t.Fatal(err)
	}
	active := func(l authtest.Login) string {
		v := decode(t, serve(h, authed(l, "GET", "/api/auth/session", "")))
		b, _ := json.Marshal(at(v, "active_roles"))
		return string(b)
	}
	if got := active(la); !strings.Contains(got, "operator") {
		t.Errorf("tenant A (default settings): active roles %s", got)
	}
	if got := active(lb); strings.Contains(got, "operator") {
		t.Errorf("tenant B (require_phr_for_all): active roles %s", got)
	}
	if rec := serve(h, authed(lb, "GET", "/api/identities", "")); rec.Code != 403 || !strings.Contains(rec.Body.String(), "role_inactive") {
		t.Errorf("tenant B operator without phr: %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(h, authed(la, "GET", "/api/identities", "")); rec.Code != 200 {
		t.Errorf("tenant A operator: %d", rec.Code)
	}
	pb := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op2@x.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	if got := active(pb); !strings.Contains(got, "operator") {
		t.Errorf("tenant B operator with phr: active roles %s", got)
	}
}
