package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// JIT eligibility as code through the API (issue #651, AC-5): export, validate and plan change nothing; an apply is
// a change request that a different admin approves, and approving it applies exactly the plan that was filed.
func TestPolicyJitAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "alice")
	ta1 := reqLogin(t, f, "ta1@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	ta2 := reqLogin(t, f, "ta2@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	eng, prod := "okta:"+groupName(t, f, "group:okta:eng"), "aws:"+groupName(t, f, "group:aws:ProdAdmin")

	if rec := reqDo(h, viewer, "POST", "/api/policy/jit/plan", `{"files":{}}`); rec.Code != 403 {
		t.Errorf("a viewer planned: %d", rec.Code)
	}
	rec := reqDo(h, pa, "GET", "/api/policy/jit/export", "")
	if rec.Code != 200 {
		t.Fatalf("export: %d %s", rec.Code, rec.Body)
	}
	var exp struct {
		Tenant string            `json:"tenant"`
		Files  map[string]string `json:"files"`
		Digest string            `json:"bundle_sha256"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Tenant != f.B.Slug || !strings.Contains(exp.Files["tessera.yaml"], "jit_enforce: false") || len(exp.Digest) != 64 {
		t.Fatalf("export = %+v", exp)
	}
	req := func(files map[string]string) string {
		raw, _ := json.Marshal(map[string]any{"commit": "c0ffee", "files": files})
		return string(raw)
	}
	files := map[string]string{
		"tessera.yaml":        fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n  jit: partial\njit_enforce: true\n", f.B.Slug),
		"jit/prod-admin.yaml": fmt.Sprintf("schema: tessera.jit/v1\nkey: prod-admin\nprincipals: [%s]\nentitlements: [%s]\nmax_hours: 4\nstep_up: true\n", eng, prod),
	}
	rec = reqDo(h, pa, "POST", "/api/policy/jit/plan", req(files))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rules_created":1`) || !strings.Contains(rec.Body.String(), `"plan_sha256":"`) ||
		!strings.Contains(rec.Body.String(), `"wanted":true`) {
		t.Fatalf("plan: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, pa, "POST", "/api/policy/jit/validate", req(files)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"valid":true`) {
		t.Errorf("validate: %d %s", rec.Code, rec.Body)
	}
	// findings come back together, with path and code
	bad := map[string]string{"tessera.yaml": strings.Replace(files["tessera.yaml"], f.B.Slug, "globex", 1),
		"jit/prod-admin.yaml": strings.Replace(files["jit/prod-admin.yaml"], "okta:", "nowhere:", 1)}
	rec = reqDo(h, pa, "POST", "/api/policy/jit/plan", req(bad))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"invalid_bundle"`) || !strings.Contains(rec.Body.String(), `"tenant_mismatch"`) ||
		!strings.Contains(rec.Body.String(), `"unknown_group"`) || !strings.Contains(rec.Body.String(), `"path":"jit/prod-admin.yaml"`) {
		t.Errorf("invalid bundle: %d %s", rec.Code, rec.Body)
	}
	huge := map[string]string{"tessera.yaml": files["tessera.yaml"], "jit/x.yaml": strings.Repeat("a", 300<<10)}
	if rec := reqDo(h, pa, "POST", "/api/policy/jit/plan", req(huge)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "too_large") {
		t.Errorf("an oversized file: %d %.200s", rec.Code, rec.Body)
	}

	// applying files a change request; a policy admin cannot file one, the filer cannot approve it
	if rec := reqDo(h, pa, "POST", "/api/policy/jit/apply", req(files)); rec.Code != 403 {
		t.Errorf("a policy admin filed an apply: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, ta1, "POST", "/api/policy/jit/apply", req(files))
	if rec.Code != 201 {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	var filed struct {
		Change struct {
			ID          string `json:"id"`
			Type        string `json:"type"`
			Status      string `json:"status"`
			TwoPerson   bool   `json:"two_person"`
			PayloadHash string `json:"payload_hash"`
		} `json:"change_request"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &filed); err != nil {
		t.Fatal(err)
	}
	if filed.Change.Type != "jit.bundle.apply" || !filed.Change.TwoPerson || filed.Change.Status != "pending_approval" {
		t.Fatalf("filed = %s", rec.Body)
	}
	enforced := func() bool {
		var on bool
		err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
			s, err := c.JITSettings()
			on = s.Enabled
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return on
	}
	if enforced() {
		t.Fatal("a request applied before its approval")
	}
	approve := fmt.Sprintf(`{"payload_hash":%q}`, filed.Change.PayloadHash)
	if rec := reqDo(h, ta1, "POST", "/api/admin/change-requests/"+filed.Change.ID+"/approve", approve); rec.Code != 403 {
		t.Errorf("self-approval: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, ta2, "POST", "/api/admin/change-requests/"+filed.Change.ID+"/approve", approve); rec.Code != 200 {
		t.Fatalf("approval: %d %s", rec.Code, rec.Body)
	}
	if !enforced() {
		t.Fatal("the approved bundle was not applied")
	}
	// the same bundle again plans as no change, and the export of the result is that bundle
	rec = reqDo(h, pa, "POST", "/api/policy/jit/plan", req(files))
	if !strings.Contains(rec.Body.String(), `"rules_unchanged":1`) {
		t.Errorf("plan after apply: %s", rec.Body)
	}
	rec = reqDo(h, pa, "GET", "/api/policy/jit/export", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	rec = reqDo(h, pa, "POST", "/api/policy/jit/plan", req(exp.Files))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rules_unchanged":1`) || !strings.Contains(rec.Body.String(), `"rules_created":0`) {
		t.Errorf("round trip plan: %d %s", rec.Code, rec.Body)
	}
	// nothing leaked into the other tenant
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if es, err := c.JITEligibilities(); err != nil || len(es) != 0 {
			t.Errorf("tenant A got %v, %v", es, err)
		}
		if s, err := c.JITSettings(); err != nil || s.Enabled {
			t.Errorf("tenant A's enforcement = %v, %v", s, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
