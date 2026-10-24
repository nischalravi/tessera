package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func v1Fixture(t *testing.T, dep ...Deprecation) (*storetest.Fixture, testSrv) {
	t.Helper()
	f := storetest.TwoTenants(t)
	srv := asAdmin(t, newIsolationServerWith(f, func(c *Config) { c.Deprecations = dep }), f.DB, f.B.ID, storetest.Now)
	return f, srv
}

// TestV1_SameAnswerAsUnversioned: /api/v1/<x> is the route /api/<x>: same
// status and body, same auth (a request without a session is refused), same
// audit event.
func TestV1_SameAnswerAsUnversioned(t *testing.T) {
	t.Parallel()
	f, srv := v1Fixture(t)
	h := srv.Handler()
	alice := fmt.Sprint(f.B.IDs["alice"])
	for _, p := range []string{"/api/summary", "/api/identities", "/api/identities/" + alice, "/api/audit?limit=5", "/api/health"} {
		old := serveOnce(h, "GET", p, "")
		v1 := serveOnce(h, "GET", strings.Replace(p, "/api/", "/api/v1/", 1), "")
		if old.Code != 200 || v1.Code != old.Code || v1.Body.String() != old.Body.String() {
			t.Errorf("%s: v1 status %d, unversioned %d; bodies equal %v", p, v1.Code, old.Code, v1.Body.String() == old.Body.String())
		}
		if v1.Header().Get("Tessera-API-Version") != "1" || old.Header().Get("Tessera-API-Version") != "" {
			t.Errorf("%s: version header v1 %q, unversioned %q", p, v1.Header().Get("Tessera-API-Version"), old.Header().Get("Tessera-API-Version"))
		}
	}
	// a write goes through the same checks and writes its events
	if rec := serveOnce(h, "POST", "/api/v1/jit/sweep", `{}`); rec.Code != 200 {
		t.Errorf("v1 sweep: %d %.200s", rec.Code, rec.Body.String())
	}
	// unknown and unversioned-only paths behave as before
	for p, want := range map[string]int{"/api/v1/no-such-route": 404, "/api/v1/": 404, "/api/v1": 404, "/api/v1/../v1/summary": 404} {
		if rec := serveOnce(h, "GET", p, ""); rec.Code != want {
			t.Errorf("%s: %d, want %d", p, rec.Code, want)
		}
	}
	// no session: refused, as the unversioned path is
	anon := newIsolationServer(f).Handler()
	if a, b := serveOnce(anon, "GET", "/api/summary", ""), serveOnce(anon, "GET", "/api/v1/summary", ""); a.Code != 401 || b.Code != 401 || a.Body.String() != b.Body.String() {
		t.Errorf("anonymous: %d vs %d", a.Code, b.Code)
	}
	// SCIM and OAuth keep their own paths; they are not aliased
	if rec := serveOnce(anon, "GET", "/api/v1/../scim/v2/Users", ""); rec.Code == 200 {
		t.Errorf("scim reached through /api/v1: %d", rec.Code)
	}
}

// TestV1_AuditedAsTheRoute: a v1 request writes one http.request event naming
// the route template.
func TestV1_AuditedAsTheRoute(t *testing.T) {
	t.Parallel()
	f, srv := v1Fixture(t)
	h := srv.Handler()
	before := httpEvents(ledger(t, f.DB, f.B.ID))
	if rec := serveOnce(h, "GET", "/api/v1/identities/"+fmt.Sprint(f.B.IDs["alice"]), ""); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	after := httpEvents(ledger(t, f.DB, f.B.ID))
	if len(after) != len(before)+1 {
		t.Fatalf("%d events, want 1", len(after)-len(before))
	}
	var hf httpField
	if err := json.Unmarshal(after[0].HTTP, &hf); err != nil {
		t.Fatal(err)
	}
	if hf.Route == nil || *hf.Route != "/api/identities/{identity_id}" || hf.Status != 200 {
		t.Errorf("http %+v", hf)
	}
}

// TestV1_DeprecationHeaders: a deprecated route answers with Deprecation and
// Sunset (and Link) on v1 only; other routes carry none.
func TestV1_DeprecationHeaders(t *testing.T) {
	t.Parallel()
	dep := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	sun := dep.AddDate(0, 7, 0)
	_, srv := v1Fixture(t, Deprecation{Method: "GET", Pattern: "/api/violations", Deprecated: dep, Sunset: sun, Link: "https://docs.example.com/migrate"})
	h := srv.Handler()
	rec := serveOnce(h, "GET", "/api/v1/violations", "")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if got, want := rec.Header().Get("Deprecation"), fmt.Sprintf("@%d", dep.Unix()); got != want {
		t.Errorf("Deprecation = %q, want %q", got, want)
	}
	if got, want := rec.Header().Get("Sunset"), sun.Format(http.TimeFormat); got != want {
		t.Errorf("Sunset = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Link"); got != `<https://docs.example.com/migrate>; rel="deprecation"` {
		t.Errorf("Link = %q", got)
	}
	for _, p := range []string{"/api/v1/summary"} {
		if r := serveOnce(h, "GET", p, ""); r.Header().Get("Deprecation") != "" || r.Header().Get("Sunset") != "" {
			t.Errorf("%s carries deprecation headers", p)
		}
	}
	if r := serveOnce(h, "GET", "/api/violations", ""); r.Header().Get("Deprecation") != "" {
		t.Error("the unversioned path carries deprecation headers")
	}
}

// TestV1_DeprecationPolicy: less than six months' notice, or an unknown route,
// is refused at startup.
func TestV1_DeprecationPolicy(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	dep := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	for name, d := range map[string]Deprecation{
		"short notice":     {Method: "GET", Pattern: "/api/violations", Deprecated: dep, Sunset: dep.AddDate(0, 5, 0)},
		"sunset first":     {Method: "GET", Pattern: "/api/violations", Deprecated: dep, Sunset: dep.AddDate(0, -1, 0)},
		"unknown route":    {Method: "GET", Pattern: "/api/no-such", Deprecated: dep, Sunset: dep.AddDate(1, 0, 0)},
		"not an api route": {Method: "GET", Pattern: "/scim/v2/Users", Deprecated: dep, Sunset: dep.AddDate(1, 0, 0)},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: accepted", name)
				}
			}()
			newIsolationServerWith(f, func(c *Config) { c.Deprecations = []Deprecation{d} })
		}()
	}
	// exactly six months of 30 days passes
	newIsolationServerWith(f, func(c *Config) {
		c.Deprecations = []Deprecation{{Method: "GET", Pattern: "/api/violations", Deprecated: dep, Sunset: dep.Add(minSunsetNotice)}}
	})
}

// TestV1_DPoPProofBoundToRequestedPath: a DPoP proof is checked against the
// path the client sent, so a DPoP-bound machine client can use /api/v1.
func TestV1_DPoPProofBoundToRequestedPath(t *testing.T) {
	e := newOAuthEnv(t)
	m := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read"}, true)
	tok := e.machineToken(m, "tenant-a", "tessera:read")
	if rec := e.call(tok, "GET", "/api/v1/summary", ""); rec.Code != 200 {
		t.Fatalf("proof for /api/v1/summary on /api/v1/summary: %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(tok, "GET", "/api/summary", ""); rec.Code != 200 {
		t.Errorf("unversioned path: %d", rec.Code)
	}
	// a proof made for the other path is refused
	rec := e.call(tok, "GET", "/api/v1/summary", "", func(r *http.Request) {
		r.Header.Set("DPoP", e.proof(tok.key, "GET", publicBase+"/api/summary", tok.access, ""))
	})
	if rec.Code != 401 {
		t.Errorf("a proof for /api/summary on /api/v1/summary: %d, want 401", rec.Code)
	}
}
