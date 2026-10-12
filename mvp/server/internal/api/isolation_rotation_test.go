package api

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Secret-rotation API isolation tests. storetest.TwoTenants gives both
// tenants an adapter pair, a policy, a bulk run and a pending job; tenant A's
// carry storetest.Sentinel. The server is signed in as tenant B and is handed
// tenant A's ids.

// rotCase is one call naming one of tenant A's rotation rows.
type rotCase struct {
	method string
	path   func(id string) string
	body   string
	key    string // the tenant A ref under test (Tenant.Refs)
}

func under(prefix, suffix string) func(string) string {
	return func(id string) string { return prefix + id + suffix }
}

// rotationRouteCases cover every rotation route with an id or name in its
// path (TestIsolation_RouteCrossTenant checks the coverage).
var rotationRouteCases = map[string][]rotCase{
	"GET /api/rotation/jobs/{id}":          {{method: "GET", path: under("/api/rotation/jobs/", ""), key: "rot:job"}},
	"POST /api/rotation/jobs/{id}/retry":   {{method: "POST", path: under("/api/rotation/jobs/", "/retry"), body: `{}`, key: "rot:job"}},
	"POST /api/rotation/jobs/{id}/cancel":  {{method: "POST", path: under("/api/rotation/jobs/", "/cancel"), body: `{}`, key: "rot:job"}},
	"DELETE /api/rotation/policies/{id}":   {{method: "DELETE", path: under("/api/rotation/policies/", ""), key: "rot:policy"}},
	"GET /api/rotation/bulk/{id}":          {{method: "GET", path: under("/api/rotation/bulk/", ""), key: "rot:bulk"}},
	"PUT /api/rotation/adapters/{name}":    nil, // TestIsolation_RotationAdapterNamesAreTenantScoped
	"DELETE /api/rotation/adapters/{name}": {{method: "DELETE", path: under("/api/rotation/adapters/", ""), key: "rot:adapter-name"}},
}

// rotationGetPaths are the GET routes with an id, given tenant B's own refs.
func rotationGetPaths(refs map[string]string) map[string]string {
	return map[string]string{
		"/api/rotation/jobs/{id}": "/api/rotation/jobs/" + refs["rot:job"],
		"/api/rotation/bulk/{id}": "/api/rotation/bulk/" + refs["rot:bulk"],
	}
}

func TestIsolation_RotationRouteCrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(t, f, f.B.ID).Handler()
	refs := map[string]string{}
	for k, v := range f.A.Refs {
		refs[k] = v
	}
	refs["rot:adapter-name"] = "adapter-" + storetest.Sentinel
	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	for route, cases := range rotationRouteCases {
		for i, tc := range cases {
			t.Run(route, func(t *testing.T) {
				cross := serveOnce(h, tc.method, tc.path(refs[tc.key]), tc.body)
				missing := serveOnce(h, tc.method, tc.path(missingUUID), tc.body)
				if cross.Code == http.StatusOK || cross.Code == http.StatusForbidden {
					t.Errorf("case %d: tenant A's ref answered %d: %.300s", i, cross.Code, cross.Body.String())
				}
				if leaks(cross.Body.String()) {
					t.Errorf("response leaks tenant A data: %.300s", cross.Body.String())
				}
				norm := func(s, id string) string { return strings.ReplaceAll(s, id, "<id>") }
				if cross.Code != missing.Code || norm(cross.Body.String(), refs[tc.key]) != norm(missing.Body.String(), missingUUID) {
					t.Errorf("tenant A's ref is distinguishable from a missing one:\n A: %d %.300s\n missing: %d %.300s",
						cross.Code, cross.Body.String(), missing.Code, missing.Body.String())
				}
			})
		}
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA {
		t.Error("calls made as tenant B changed tenant A")
	}
}

// Ids in request bodies: a secret, an adapter name and a bulk system of tenant A's answer as missing ones.
func TestIsolation_RotationBodyReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(t, f, f.B.ID).Handler()
	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	aSecret := itoa(f.A.IDs["secret"])
	missingSecret := itoa(missingID)
	for name, tc := range map[string]struct {
		method, path, a, missing string
	}{
		"rotate a secret": {"POST", "/api/rotation/jobs", `{"secret_id":` + aSecret + `}`, `{"secret_id":` + missingSecret + `}`},
		"plan a secret":   {"POST", "/api/rotation/plan", `{"secret_ids":[` + aSecret + `]}`, `{"secret_ids":[` + missingSecret + `]}`},
		"policy names an adapter": {"PUT", "/api/rotation/policies",
			`{"kind":"api_key","max_age_days":30,"adapter":"adapter-` + storetest.Sentinel + `","destination":"dest-` + storetest.Sentinel + `","dest_path":"kv/x"}`,
			`{"kind":"api_key","max_age_days":30,"adapter":"adapter-nope","destination":"dest-nope","dest_path":"kv/x"}`},
	} {
		t.Run(name, func(t *testing.T) {
			cross := serveOnce(h, tc.method, tc.path, tc.a)
			missing := serveOnce(h, tc.method, tc.path, tc.missing)
			if cross.Code == http.StatusOK || cross.Code == http.StatusCreated || cross.Code == http.StatusForbidden {
				t.Errorf("answered %d: %.300s", cross.Code, cross.Body.String())
			}
			norm := func(s string) string {
				return strings.NewReplacer(aSecret, "<id>", missingSecret, "<id>", storetest.Sentinel, "nope", "-nope", "-nope").Replace(s)
			}
			if cross.Code != missing.Code || norm(cross.Body.String()) != norm(missing.Body.String()) {
				t.Errorf("indistinguishable check failed:\n A: %d %.300s\n missing: %d %.300s", cross.Code, cross.Body.String(), missing.Code, missing.Body.String())
			}
		})
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA {
		t.Error("calls made as tenant B changed tenant A")
	}
}

// Adapter names are unique per tenant: B creating an adapter with A's name
// makes B's own and leaves A's alone.
func TestIsolation_RotationAdapterNamesAreTenantScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(t, f, f.B.ID).Handler()
	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	name := "adapter-" + storetest.Sentinel
	rec := serveOnce(h, "PUT", "/api/rotation/adapters/"+name, `{"type":"fake","config":{"fail_at":"create"}}`)
	// tenant B has its own adapter of that name? B's fixture names carry no sentinel, so this creates it
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT: %d %.300s", rec.Code, rec.Body.String())
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA {
		t.Error("B's adapter write changed tenant A")
	}
}

// Rotation lists show a tenant its own rows only; as tenant A the sentinel is there (positive control).
func TestIsolation_RotationListsNeverLeak(t *testing.T) {
	f := storetest.TwoTenants(t)
	asA := isolationServer(t, f, f.A.ID).Handler()
	asB := isolationServer(t, f, f.B.ID).Handler()
	for _, path := range []string{"/api/rotation/adapters", "/api/rotation/policies", "/api/rotation/jobs", "/api/rotation/bulk",
		"/api/rotation/overview"} {
		a := serveOnce(asA, "GET", path, "")
		b := serveOnce(asB, "GET", path, "")
		if a.Code != 200 || b.Code != 200 {
			t.Errorf("%s: %d / %d", path, a.Code, b.Code)
			continue
		}
		if !leaks(a.Body.String()) && path != "/api/rotation/overview" && path != "/api/rotation/policies" {
			t.Errorf("%s as tenant A does not show its sentinel (the leak check would never fire)", path)
		}
		if leaks(b.Body.String()) {
			t.Errorf("%s as tenant B leaks tenant A's data", path)
		}
	}
	for _, tc := range []struct{ path, body string }{{"/api/rotation/plan", `{}`}, {"/api/rotation/bulk/plan", `{"system":"aws"}`}} {
		if rec := serveOnce(asB, "POST", tc.path, tc.body); rec.Code != 200 || leaks(rec.Body.String()) {
			t.Errorf("%s as tenant B: %d, leaks=%v", tc.path, rec.Code, leaks(rec.Body.String()))
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
