package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Deployment-readiness API isolation tests. storetest.TwoTenants gives both
// tenants the same readiness rows; tenant B's carry
// storetest.ReadinessSentinel. The server is bound to tenant A and is handed
// tenant B's connection, revision, run and finding ids.

// missingUUID is a readiness id no fixture row has.
const missingUUID = "00000000-0000-4000-8000-00000000dead"

func readinessLeaks(body string) bool {
	return strings.Contains(strings.ToLower(body), strings.ToLower(storetest.ReadinessSentinel))
}

// rdCase is one call naming a tenant B readiness row. path and body receive
// tenant A's refs (for the parts of the path that are A's own) and the ref
// under test, which is B's id or missingUUID.
type rdCase struct {
	method string
	path   func(a map[string]string, id string) string
	body   string
	key    string // the tenant B ref under test
}

func onConn(suffix string) func(map[string]string, string) string {
	return func(_ map[string]string, id string) string { return "/api/connections/" + id + suffix }
}

// readinessRouteCases cover every readiness route with an id in its path
// (TestIsolation_RouteCrossTenant checks the coverage).
var readinessRouteCases = map[string][]rdCase{
	"GET /api/connections/{id}": {{method: "GET", path: onConn(""), key: "connection:ad"}},
	"PATCH /api/connections/{id}/config": {{method: "PATCH", path: onConn("/config"), body: `{"stale_days":60}`,
		key: "connection:ad"}},
	"PUT /api/connections/{id}/credential": {{method: "PUT", path: onConn("/credential"),
		body: `{"reference":"vault:kv/tessera/other"}`, key: "connection:ad"}},
	"PUT /api/connections/{id}/containment-credential": {{method: "PUT", path: onConn("/containment-credential"),
		body: `{"token":"tok-from-another-tenant","base_url":"https://x.okta.com"}`, key: "connection"}},
	"GET /api/connections/{id}/checklist": {{method: "GET", path: onConn("/checklist"), key: "connection:ad"}},
	"POST /api/connections/{id}/checklist/{item}/attest": {{method: "POST", path: onConn("/checklist/base.owner/attest"),
		body: `{"note":"attested from another tenant"}`, key: "connection:ad"}},
	"POST /api/connections/{id}/checklist/{item}/attest-instead": {{method: "POST", path: onConn("/checklist/ldap.svc.no_write/attest-instead"),
		body: `{"attester":"Pat","reason":"attested from another tenant","evidence":"none at all"}`, key: "connection:ad"}},
	"POST /api/connections/{id}/checklist/{item}/skip": {{method: "POST", path: onConn("/checklist/base.schedule/skip"),
		body: `{"reason":"skipping across the tenant boundary"}`, key: "connection:ad"}},
	// The fixture skips the same item in both tenants.
	"DELETE /api/connections/{id}/checklist/{item}/skip": {{method: "DELETE", path: func(a map[string]string, id string) string {
		return "/api/connections/" + id + "/checklist/" + a["item:ad-skip"] + "/skip"
	}, key: "connection:ad"}},
	"POST /api/connections/{id}/transition": {{method: "POST", path: onConn("/transition"),
		body: `{"to":"ready_to_validate"}`, key: "connection:ad"}},
	"POST /api/connections/{id}/activate":  {{method: "POST", path: onConn("/activate"), key: "connection"}},
	"GET /api/connections/{id}/activation": {{method: "GET", path: onConn("/activation"), key: "connection"}},
	"POST /api/connections/{id}/activation/approve": {{method: "POST", path: onConn("/activation/approve"),
		key: "connection"}},
	"POST /api/connections/{id}/activation/reject": {{method: "POST", path: onConn("/activation/reject"),
		key: "connection"}},
	"POST /api/connections/{id}/retire": {{method: "POST", path: onConn("/retire"), body: `{"confirm":true}`,
		key: "connection:ad"}},
	"POST /api/connections/{id}/validate": {{method: "POST", path: onConn("/validate"), key: "connection"}},
	"GET /api/connections/{id}/validations/{run}": {
		{method: "GET", path: func(a map[string]string, id string) string {
			return "/api/connections/" + a["connection:ad"] + "/validations/" + id
		}, key: "run:ad-live"},
		{method: "GET", path: onConn("/validations/" + missingUUID), key: "connection:ad"},
	},
	"POST /api/connections/{id}/dry-run": {{method: "POST", path: onConn("/dry-run"), key: "connection"}},
	"GET /api/connections/{id}/dry-runs/{run}": {
		{method: "GET", path: func(a map[string]string, id string) string {
			return "/api/connections/" + a["connection:ad"] + "/dry-runs/" + id
		}, key: "run:ad-dry"},
		{method: "GET", path: onConn("/dry-runs/" + missingUUID), key: "connection:ad"},
	},
	"GET /api/connections/{id}/findings": {
		{method: "GET", path: onConn("/findings"), key: "connection:ad"},
		{method: "GET", path: func(a map[string]string, id string) string {
			return "/api/connections/" + a["connection:ad"] + "/findings?run=" + id
		}, key: "run:ad-dry"},
	},
	"POST /api/connections/{id}/findings/{fid}/accept": {
		{method: "POST", path: func(a map[string]string, id string) string {
			return "/api/connections/" + a["connection:ad"] + "/findings/" + id + "/accept"
		}, body: `{"reason":"accepting a finding of another tenant"}`, key: "finding:ad"},
		{method: "POST", path: onConn("/findings/" + missingUUID + "/accept"),
			body: `{"reason":"accepting a finding of another tenant"}`, key: "connection:ad"},
	},
	"GET /api/connections/{id}/health": {{method: "GET", path: onConn("/health"), key: "connection:ad"}},
	// Template routes take a template id, which every tenant shares: see
	// TestIsolation_ReadinessListRoutesNeverLeak (GET) and
	// TestIsolation_ReadinessOverlayScoped (PUT).
	"GET /api/readiness/templates/{type}": nil,
	"PUT /api/readiness/overlays/{type}":  nil,
}

// TestIsolation_ReadinessRouteCrossTenant: as tenant A, every readiness route
// given tenant B's connection, run or finding id answers exactly as for an
// id that exists nowhere (same status and body), never 200 or 403, never
// with B's data, and tenant B is left untouched.
func TestIsolation_ReadinessRouteCrossTenant(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	h := isolationServer(t, f, f.A.ID).Handler()
	beforeB := storetest.ReadinessDump(t, f.DB, f.B.ID, f.B.Refs)
	beforeBGraph := storetest.Dump(t, f.DB, f.B.ID)
	for route, cases := range readinessRouteCases {
		for i, tc := range cases {
			t.Run(route+"#"+string(rune('0'+i)), func(t *testing.T) {
				bID := f.B.Refs[tc.key]
				if bID == "" {
					t.Fatalf("fixture has no tenant B ref %q", tc.key)
				}
				cross := serveOnce(h, tc.method, tc.path(f.A.Refs, bID), tc.body)
				missing := serveOnce(h, tc.method, tc.path(f.A.Refs, missingUUID), tc.body)
				if cross.Code == http.StatusOK || cross.Code == http.StatusCreated || cross.Code == http.StatusAccepted {
					t.Errorf("tenant B's id answered %d: %.300s", cross.Code, cross.Body.String())
				}
				if cross.Code == http.StatusForbidden {
					t.Error("tenant B's id answered 403, which reveals it exists")
				}
				if readinessLeaks(cross.Body.String()) || leaks(cross.Body.String()) {
					t.Errorf("response leaks another tenant's data: %.300s", cross.Body.String())
				}
				norm := func(s, id string) string {
					return strings.ReplaceAll(strings.ReplaceAll(s, id, "<id>"), missingUUID, "<id>")
				}
				if cross.Code != missing.Code || norm(cross.Body.String(), bID) != norm(missing.Body.String(), missingUUID) {
					t.Errorf("tenant B's id is distinguishable from a missing one:\n B: %d %.300s\n missing: %d %.300s",
						cross.Code, cross.Body.String(), missing.Code, missing.Body.String())
				}
			})
		}
	}
	if storetest.ReadinessDump(t, f.DB, f.B.ID, f.B.Refs) != beforeB {
		t.Error("readiness calls made as tenant A changed tenant B's readiness rows")
	}
	if storetest.Dump(t, f.DB, f.B.ID) != beforeBGraph {
		t.Error("readiness calls made as tenant A changed tenant B's graph or audit log")
	}
}

// readinessGetPaths fills the path parameters of the readiness GET routes
// with one tenant's own ids.
func readinessGetPaths(r map[string]string) map[string]string {
	conn := "/api/connections/" + r["connection:ad"]
	return map[string]string{
		"/api/readiness/templates/{type}":              "/api/readiness/templates/ad",
		"/api/connections/{id}":                        conn,
		"/api/connections/{id}/checklist":              conn + "/checklist",
		"/api/connections/{id}/activation":             conn + "/activation",
		"/api/connections/{id}/validations/{run}":      conn + "/validations/" + r["run:ad-live"],
		"/api/connections/{id}/dry-runs/{run}":         conn + "/dry-runs/" + r["run:ad-dry"],
		"/api/connections/{id}/findings":               conn + "/findings",
		"/api/connections/{id}/health":                 conn + "/health",
		"/api/readiness/templates":                     "/api/readiness/templates",
		"/api/connections":                             "/api/connections",
		"/api/insights/deployment-health":              "/api/insights/deployment-health",
		"/api/summary?include=readiness":               "/api/summary?include=readiness",
		"/api/connections/{id}?okta":                   "/api/connections/" + r["connection"],
		"/api/connections/{id}/dry-runs/{run}?okta":    "/api/connections/" + r["connection"] + "/dry-runs/" + r["run:dry"],
		"/api/connections/{id}/validations/{run}?okta": "/api/connections/" + r["connection"] + "/validations/" + r["run:live"],
	}
}

// TestIsolation_ReadinessListRoutesNeverLeak: as tenant A, every readiness
// GET route (with A's own ids) and the readiness writes that return data
// answer without any of tenant B's readiness data. Served as B, the same
// routes do show B's sentinel (positive control).
func TestIsolation_ReadinessListRoutesNeverLeak(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	srv := isolationServer(t, f, f.A.ID)
	h := srv.Handler()
	hb := isolationServer(t, f, f.B.ID).Handler()
	for _, p := range []string{"/api/connections", "/api/insights/deployment-health", "/api/readiness/templates/ad",
		"/api/connections/" + f.B.Refs["connection:ad"] + "/checklist"} {
		if rec := serveOnce(hb, http.MethodGet, p, ""); !readinessLeaks(rec.Body.String()) {
			t.Fatalf("tenant B's own %s does not carry the readiness sentinel; the leak check would never fire", p)
		}
	}
	paths := readinessGetPaths(f.A.Refs)
	for _, rt := range srv.Routes() {
		if rt.Method != http.MethodGet || !rt.Tenant {
			continue
		}
		if _, ok := paths[rt.Pattern]; !ok && (strings.HasPrefix(rt.Pattern, "/api/connections") ||
			strings.HasPrefix(rt.Pattern, "/api/readiness") || strings.HasPrefix(rt.Pattern, "/api/insights")) {
			t.Errorf("readiness GET %s has no tenant A path", rt.Pattern)
		}
	}
	check := func(method, path, body string) {
		t.Helper()
		rec := serveOnce(h, method, path, body)
		if rec.Code >= 500 {
			t.Errorf("%s %s: status %d: %.300s", method, path, rec.Code, rec.Body.String())
		}
		if readinessLeaks(rec.Body.String()) {
			t.Errorf("%s %s leaks tenant B's readiness data", method, path)
		}
	}
	for _, p := range paths {
		rec := serveOnce(h, http.MethodGet, p, "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d: %.300s", p, rec.Code, rec.Body.String())
		}
		if readinessLeaks(rec.Body.String()) {
			t.Errorf("GET %s leaks tenant B's readiness data", p)
		}
	}
	// Writes on A's own connections, then the reads again.
	a := f.A.Refs
	check("POST", "/api/connections/"+a["connection:ad"]+"/checklist/base.owner/attest", `{"note":"checked in tenant A"}`)
	check("PATCH", "/api/connections/"+a["connection:ad"]+"/config", `{"stale_days":60}`)
	check("POST", "/api/connections/"+a["connection"]+"/validate", "")
	check("POST", "/api/connections/"+a["connection"]+"/dry-run", "")
	check("POST", "/api/connections/"+a["connection"]+"/activate", "")
	check("POST", "/api/insights/deployment-health/rerun", `{"reconcile":true}`)
	check("PUT", "/api/readiness/overlays/ad", `{"raise_levels":{"ad.svc.no_interactive":"required"}}`)
	check("POST", "/api/connections", `{"name":"Workday (demo)","connector_type":"demo-workday"}`)
	for _, p := range paths {
		if rec := serveOnce(h, http.MethodGet, p, ""); readinessLeaks(rec.Body.String()) {
			t.Errorf("after writes, GET %s leaks tenant B's readiness data", p)
		}
	}
}

// TestIsolation_ReadinessOverlayScoped: an overlay written by tenant A
// changes only A's view of the shared template, and B's overlay never shows
// in A.
func TestIsolation_ReadinessOverlayScoped(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	ha, hb := isolationServer(t, f, f.A.ID).Handler(), isolationServer(t, f, f.B.ID).Handler()
	beforeB := serveOnce(hb, http.MethodGet, "/api/readiness/templates/ad", "").Body.String()
	rec := serveOnce(ha, http.MethodPut, "/api/readiness/overlays/ad",
		`{"raise_levels":{"ad.svc.no_interactive":"required"}}`)
	if rec.Code != http.StatusOK || readinessLeaks(rec.Body.String()) {
		t.Fatalf("PUT overlay as A: %d %.300s", rec.Code, rec.Body.String())
	}
	if after := serveOnce(hb, http.MethodGet, "/api/readiness/templates/ad", "").Body.String(); after != beforeB {
		t.Error("tenant A's overlay changed tenant B's template")
	}
}

// TestIsolation_ReadinessAuditStampedWithOwnTenant: the audit entries of an
// attestation, a skip and an activation attempt made as tenant A land in A's
// audit log only.
func TestIsolation_ReadinessAuditStampedWithOwnTenant(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	h := isolationServer(t, f, f.A.ID).Handler()
	a := f.A.Refs
	countIn := func(tn storetest.Tenant) map[string]int {
		out := map[string]int{}
		if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			log, err := c.AuditLog(-1)
			for _, e := range log {
				out[e.Action]++
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	beforeA, beforeB := countIn(f.A), countIn(f.B)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/connections/" + a["connection:ad"] + "/checklist/base.owner/attest", `{"note":"re-attested by tenant A"}`},
		{"DELETE", "/api/connections/" + a["connection:ad"] + "/checklist/" + a["item:ad-skip"] + "/skip", ""},
		{"POST", "/api/connections/" + a["connection:ad"] + "/checklist/" + a["item:ad-skip"] + "/skip",
			`{"reason":"accepted gap until the Q1 migration"}`},
	} {
		if rec := serveOnce(h, c.method, c.path, c.body); rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %.300s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	afterA, afterB := countIn(f.A), countIn(f.B)
	for _, action := range []string{"readiness.item.attested", "readiness.item.unskipped", "readiness.item.skipped"} {
		if afterA[action] != beforeA[action]+1 {
			t.Errorf("tenant A has %d %s events, want %d", afterA[action], action, beforeA[action]+1)
		}
	}
	for action, n := range afterB {
		if n != beforeB[action] {
			t.Errorf("tenant A's calls added %s events to tenant B", action)
		}
	}
}
