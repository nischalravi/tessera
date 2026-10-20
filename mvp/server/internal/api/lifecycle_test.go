package api

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestLifecycleAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	b := f.B.IDs
	path := fmt.Sprintf("/api/identities/%d/lifecycle", b["alice"])
	end := storetest.Now.Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)

	// an employee by default
	if rec := reqDo(h, alice, "GET", path, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"default":true`) {
		t.Fatalf("default: %d %s", rec.Code, rec.Body)
	}
	body := fmt.Sprintf(`{"worker_type":"contractor","sponsor_identity_id":%d,"organization":"Acme Consulting","ends_at":"%s","reason":"SOW 42"}`, b["carol"], end)
	if rec := reqDo(h, carol, "PUT", path, body); rec.Code != 403 {
		t.Errorf("viewer sets: %d", rec.Code)
	}
	rec := reqDo(h, admin, "PUT", path, body)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"worker_type":"contractor"`) || !strings.Contains(rec.Body.String(), `"state":"ending"`) {
		t.Fatalf("set: %d %s", rec.Code, rec.Body)
	}
	// carol sponsors alice: she sees her and may extend; alice may not extend herself
	rec = reqDo(h, carol, "GET", "/api/lifecycle/sponsored", "")
	if !strings.Contains(rec.Body.String(), fmt.Sprintf(`"id":%d`, b["alice"])) || !strings.Contains(rec.Body.String(), `"can_extend":true`) {
		t.Errorf("sponsored: %s", rec.Body)
	}
	later := storetest.Now.Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	ext := fmt.Sprintf(`{"ends_at":"%s","reason":"renewed"}`, later)
	if rec := reqDo(h, alice, "POST", path+"/extend", ext); rec.Code != 403 || !strings.Contains(rec.Body.String(), "not_sponsor") {
		t.Errorf("alice extends: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, carol, "POST", path+"/extend", ext); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"event":"extended"`) {
		t.Fatalf("carol extends: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "GET", "/api/lifecycle?state=active", ""); !strings.Contains(rec.Body.String(), "Acme Consulting") {
		t.Errorf("list active: %s", rec.Body)
	}
	if rec := reqDo(h, admin, "GET", "/api/lifecycle?state=bogus", ""); rec.Code != 422 {
		t.Errorf("bad state: %d", rec.Code)
	}
	// a term due in a day is warned by the sweep
	soon := storetest.Now.Add(20 * time.Hour).UTC().Format(time.RFC3339)
	bob := fmt.Sprintf("/api/identities/%d/lifecycle", b["bob"])
	if rec := reqDo(h, admin, "PUT", bob, fmt.Sprintf(`{"worker_type":"vendor","sponsor_identity_id":%d,"ends_at":"%s","reason":"x"}`, b["carol"], soon)); rec.Code != 200 {
		t.Fatalf("bob: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, carol, "POST", "/api/lifecycle/sweep", ""); rec.Code != 403 {
		t.Errorf("viewer sweeps: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "POST", "/api/lifecycle/sweep", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"warned":1`) {
		t.Errorf("sweep: %d %s", rec.Code, rec.Body)
	}
	acts := reqAuditActions(t, f, f.B.ID)
	for a, n := range map[string]int{"lifecycle.set": 2, "lifecycle.extend": 1, "lifecycle.warn": 1} {
		if acts[a] != n {
			t.Errorf("audit %s = %d, want %d", a, acts[a], n)
		}
	}
	// a stale sign-in must step up before setting a lifecycle
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := serve(h, authed(stale, "PUT", path, body)); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale set: %d %s", rec.Code, rec.Body)
	}
}
