package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Route coverage (design §19 PR5, §20 E2.1–E2.3): every route is enumerated
// from Server.Routes(); none can be added without a declared permission or
// a reviewed change to the public allow-list.

var paramRE = regexp.MustCompile(`\{([a-z_]+)\}`)

// concretePath fills a route pattern's parameters with ids of tenant t's
// fixture rows where they exist, and with well-formed unknown ids otherwise.
func concretePath(pattern string, t storetest.Tenant) string {
	return paramRE.ReplaceAllStringFunc(pattern, func(m string) string {
		switch m[1 : len(m)-1] {
		case "identity_id":
			return fmt.Sprint(t.IDs["alice"])
		case "campaign_id":
			return fmt.Sprint(t.IDs["campaign"])
		case "item_id":
			return fmt.Sprint(t.IDs["item"])
		case "request_id":
			return fmt.Sprint(t.IDs["request:pending"])
		case "event_id":
			if strings.HasPrefix(pattern, "/api/hris/") {
				return fmt.Sprint(t.IDs["hris:joiner"])
			}
		case "type":
			return "demo-ad"
		case "item":
			return "base.owner"
		}
		return "00000000-0000-4000-8000-00000000dead"
	})
}

// routeRequest builds a request for a route (a JSON body on unsafe methods).
func routeRequest(rt RouteInfo, t storetest.Tenant) *http.Request {
	var req *http.Request
	path := concretePath(rt.Pattern, t)
	if rt.Method == http.MethodGet || rt.Method == http.MethodDelete {
		req = httptest.NewRequest(rt.Method, path, nil)
	} else {
		req = httptest.NewRequest(rt.Method, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestAllRoutesRequireAuth (E2.1): every route that is not on the public
// allow-list answers 401 login_required without a session, with an unknown
// session, with an expired one and with a bearer token (token principals
// arrive in PR10); the allow-list is snapshot-tested.
func TestAllRoutesRequireAuth(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	srv := isolationServer(t, f, f.B.ID)
	h := srv.Anonymous()
	expired := signIn(t, f.DB, f.B.ID, authtest.User{Email: "old@b.example", Roles: testAdmin.Roles}, authtest.Phr,
		storetest.Now.Add(-48*time.Hour))
	credentials := map[string]func(*http.Request){
		"none":           func(*http.Request) {},
		"unknown cookie": func(r *http.Request) { r.AddCookie(auth.Cookies{}.Session(auth.NewSecret())) },
		"expired session": func(r *http.Request) {
			expired.Apply(r)
		},
		"bearer token": func(r *http.Request) { r.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIn0.e30.") },
		"dpop token": func(r *http.Request) {
			r.Header.Set("Authorization", "DPoP eyJhbGciOiJub25lIn0.e30.")
			r.Header.Set("DPoP", "x")
		},
	}
	var public []string
	for _, rt := range srv.Routes() {
		if rt.Public {
			public = append(public, rt.Method+" "+rt.Pattern)
			continue
		}
		for name, apply := range credentials {
			req := routeRequest(rt, f.B)
			apply(req)
			rec := serve(h, req)
			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"login_required"`) {
				t.Errorf("%s %s (%s): %d %.200s, want 401 login_required", rt.Method, rt.Pattern, name, rec.Code, rec.Body.String())
			}
			if leaks(rec.Body.String()) {
				t.Errorf("%s %s (%s) leaks data", rt.Method, rt.Pattern, name)
			}
		}
	}
	golden := "../../testdata/contract/public_routes.golden"
	want, err := os.ReadFile(golden) // #nosec G304 -- fixed test path
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(public, "\n") + "\n"; got != string(want) {
		t.Errorf("public routes changed (review the change, then update %s):\n%s", golden, got)
	}
	for _, p := range public {
		if !isPublicRoute(strings.SplitN(p, " ", 2)[0], strings.SplitN(p, " ", 2)[1]) {
			t.Errorf("%s is public but not on the allow-list", p)
		}
	}
}

// TestAllRoutesDeclarePermission (E2.2): every non-public route declares a
// permission, and registration without one (or a public route off the
// allow-list, or a public route reaching tenant data) panics at startup.
func TestAllRoutesDeclarePermission(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	perms := map[auth.Permission]bool{}
	for _, p := range auth.AllPermissions() {
		perms[p] = true
	}
	for _, rt := range srv.Routes() {
		if rt.Public {
			if rt.Perm != "" || rt.Authn != nil || rt.Tenant {
				t.Errorf("public route %s %s declares %q or reaches tenant data", rt.Method, rt.Pattern, rt.Perm)
			}
			continue
		}
		if !perms[rt.Perm] {
			t.Errorf("route %s %s declares unknown permission %q", rt.Method, rt.Pattern, rt.Perm)
		}
	}
	nop := func(http.ResponseWriter, *http.Request, *params) (any, error) { return nil, nil }
	for name, register := range map[string]func(){
		"no permission":       func() { srv.handle(http.MethodGet, "/api/x1", read, Route{}, nop) },
		"public, not allowed": func() { srv.handle(http.MethodGet, "/api/x2", noTenant, publicRoute, nop) },
		"public with tenant":  func() { srv.handle(http.MethodGet, "/api/health", read, publicRoute, nop) },
		"public with permission": func() {
			srv.handle(http.MethodGet, "/api/health", noTenant, Route{Public: true, Perm: auth.PermGraphRead}, nop)
		},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: registration did not panic", name)
				}
			}()
			register()
		}()
	}
}

// TestEveryCallAudited (E2.3): one authenticated call to any route writes
// exactly one http.request event in the principal's tenant, with the
// route's pattern, the principal as actor and the authn summary; a 401 is
// recorded on the platform chain as anonymous; a 403 is recorded with the
// user and outcome denied.
func TestEveryCallAudited(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	raw := srv.Handler()
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "vic@b.example", Roles: []auth.Role{auth.RoleViewer}},
		authtest.Phr, storetest.Now)
	for _, rt := range srv.Routes() {
		if rt.Pattern == "/api/health" {
			continue // excluded from http.request (§13.4)
		}
		t.Run(rt.Method+" "+rt.Pattern, func(t *testing.T) {
			// a fresh session per route: logout and session revocation end theirs
			l := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
			req := routeRequest(rt, f.B)
			if rt.Public {
				req.Header.Set("Origin", authtest.Origin)
			} else {
				l.Apply(req)
			}
			before := httpEvents(ledger(t, f.DB, f.B.ID))
			beforeP := httpEvents(ledger(t, f.DB, tenancy.Platform))
			rec := serve(raw, req)
			after := httpEvents(ledger(t, f.DB, f.B.ID))
			afterP := httpEvents(ledger(t, f.DB, tenancy.Platform))
			if rt.Public {
				if len(after)+len(afterP) != len(before)+len(beforeP)+1 {
					t.Fatalf("public call wrote %d events", len(after)+len(afterP)-len(before)-len(beforeP))
				}
				return
			}
			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Fatalf("admin call refused: %d %.200s", rec.Code, rec.Body.String())
			}
			if len(after) != len(before)+1 || len(afterP) != len(beforeP) {
				t.Fatalf("%d events in the tenant, %d on the platform chain; want exactly 1 in the tenant",
					len(after)-len(before), len(afterP)-len(beforeP))
			}
			e := after[0]
			var hf httpField
			if err := json.Unmarshal(e.HTTP, &hf); err != nil {
				t.Fatal(err)
			}
			if hf.Route == nil || *hf.Route != rt.Pattern || hf.Method != rt.Method || hf.Status != rec.Code {
				t.Errorf("http %+v, want route %s status %d", hf, rt.Pattern, rec.Code)
			}
			if e.ActorType != store.ActorUser || e.ActorID == nil || *e.ActorID != l.UserID.String() ||
				e.SessionID == nil || *e.SessionID != l.SessionID.String() || len(e.Authn) == 0 {
				t.Errorf("actor %s %v session %v authn %s", e.ActorType, e.ActorID, e.SessionID, e.Authn)
			}
			var authn store.AuditAuthn
			if err := json.Unmarshal(e.Authn, &authn); err != nil || authn.Phr == nil || !*authn.Phr || authn.AAL == nil ||
				*authn.AAL != 2 || authn.ACR == nil || *authn.ACR != string(auth.ACRPhr) || authn.AuthAgeS == nil {
				t.Errorf("authn summary %s (%v)", e.Authn, err)
			}
		})
	}
	// 401: anonymous, on the platform chain, with the reason
	before := httpEvents(ledger(t, f.DB, tenancy.Platform))
	beforeB := httpEvents(ledger(t, f.DB, f.B.ID))
	serve(raw, httptest.NewRequest(http.MethodGet, "/api/summary", nil))
	after := httpEvents(ledger(t, f.DB, tenancy.Platform))
	if len(after) != len(before)+1 || len(httpEvents(ledger(t, f.DB, f.B.ID))) != len(beforeB) {
		t.Fatal("a 401 was not recorded exactly once on the platform chain")
	}
	if e := after[0]; e.ActorType != store.ActorAnonymous || e.Outcome != store.OutcomeDenied ||
		!strings.Contains(string(e.Detail), `"anonymous_reason":"no_session"`) {
		t.Errorf("401 event: %s %s %s", e.ActorType, e.Outcome, e.Detail)
	}
	// 403: the user, outcome denied
	beforeB = httpEvents(ledger(t, f.DB, f.B.ID))
	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	viewer.Apply(req)
	if rec := serve(raw, req); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer reading the audit log: %d", rec.Code)
	}
	afterB := httpEvents(ledger(t, f.DB, f.B.ID))
	if len(afterB) != len(beforeB)+1 || afterB[0].ActorType != store.ActorUser || afterB[0].Outcome != store.OutcomeDenied ||
		*afterB[0].ActorID != viewer.UserID.String() {
		t.Errorf("403 event: %+v", afterB[0])
	}
}
