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

// SoD rules as code through the API (issue #652, AC-6): export, validate and plan change nothing; an apply is a
// change request that a different admin approves, and approving it applies exactly the plan that was filed.
func TestPolicySodAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "alice")
	ta1 := reqLogin(t, f, "ta1@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	ta2 := reqLogin(t, f, "ta2@b.example", []auth.Role{auth.RoleTenantAdmin}, "")

	if rec := reqDo(h, viewer, "POST", "/api/policy/sod/plan", `{"files":{}}`); rec.Code != 403 {
		t.Errorf("a viewer planned: %d", rec.Code)
	}
	rec := reqDo(h, pa, "GET", "/api/policy/sod/export", "")
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
	if exp.Tenant != f.B.Slug || !strings.Contains(exp.Files["tessera.yaml"], "sod: partial") || len(exp.Digest) != 64 {
		t.Fatalf("export = %+v", exp)
	}
	req := func(files map[string]string) string {
		raw, _ := json.Marshal(map[string]any{"commit": "c0ffee", "files": files})
		return string(raw)
	}
	doc := `schema: tessera.sod/v1
ruleset:
  key: payments
  name: Payments controls
  enabled: true
functions:
  - key: create
    name: Create a payment
    selectors: [{name_pattern: "payments:create*"}]
  - key: approve
    name: Approve a payment
    selectors: [{name_pattern: "payments:approve*"}]
risks:
  - key: pay-create-approve
    name: Create and approve a payment
    priority: high
    functions: [create, approve]
`
	files := map[string]string{
		"tessera.yaml":      fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n  sod: partial\n", f.B.Slug),
		"sod/payments.yaml": doc,
	}
	rec = reqDo(h, pa, "POST", "/api/policy/sod/plan", req(files))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"created":4`) || !strings.Contains(rec.Body.String(), `"plan_sha256":"`) {
		t.Fatalf("plan: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, pa, "POST", "/api/policy/sod/validate", req(files)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"valid":true`) {
		t.Errorf("validate: %d %s", rec.Code, rec.Body)
	}
	// findings come back together, with path and code
	bad := map[string]string{"tessera.yaml": files["tessera.yaml"], "sod/payments.yaml": strings.Replace(doc, "priority: high", "priority: urgent", 1)}
	rec = reqDo(h, pa, "POST", "/api/policy/sod/plan", req(bad))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"invalid_bundle"`) || !strings.Contains(rec.Body.String(), `"invalid_priority"`) || !strings.Contains(rec.Body.String(), `"path":"sod/payments.yaml"`) {
		t.Errorf("invalid bundle: %d %s", rec.Code, rec.Body)
	}
	other := map[string]string{"tessera.yaml": strings.Replace(files["tessera.yaml"], f.B.Slug, "globex", 1), "sod/payments.yaml": doc}
	if rec := reqDo(h, pa, "POST", "/api/policy/sod/plan", req(other)); rec.Code != 422 || !strings.Contains(rec.Body.String(), `"tenant_mismatch"`) {
		t.Errorf("another tenant's bundle: %d %s", rec.Code, rec.Body)
	}
	huge := map[string]string{"tessera.yaml": files["tessera.yaml"], "sod/x.yaml": strings.Repeat("a", 300<<10)}
	if rec := reqDo(h, pa, "POST", "/api/policy/sod/plan", req(huge)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "too_large") {
		t.Errorf("an oversized file: %d %.200s", rec.Code, rec.Body)
	}

	// applying files a change request; a policy admin cannot file one, the filer cannot approve it
	if rec := reqDo(h, pa, "POST", "/api/policy/sod/apply", req(files)); rec.Code != 403 {
		t.Errorf("a policy admin filed an apply: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, ta1, "POST", "/api/policy/sod/apply", req(files))
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
	if filed.Change.Type != "sod.bundle.apply" || !filed.Change.TwoPerson || filed.Change.Status != "pending_approval" {
		t.Fatalf("filed = %s", rec.Body)
	}
	count := func() int {
		n := 0
		err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
			rs, err := c.SodRulesets()
			n = len(rs)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() != 0 {
		t.Fatal("a request applied before its approval")
	}
	approve := fmt.Sprintf(`{"payload_hash":%q}`, filed.Change.PayloadHash)
	if rec := reqDo(h, ta1, "POST", "/api/admin/change-requests/"+filed.Change.ID+"/approve", approve); rec.Code != 403 {
		t.Errorf("self-approval: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, ta2, "POST", "/api/admin/change-requests/"+filed.Change.ID+"/approve", approve); rec.Code != 200 {
		t.Fatalf("approval: %d %s", rec.Code, rec.Body)
	}
	if count() != 1 {
		t.Fatal("the approved bundle was not applied")
	}
	// the same bundle again plans as no change, and the export of the result is that bundle
	rec = reqDo(h, pa, "POST", "/api/policy/sod/plan", req(files))
	if !strings.Contains(rec.Body.String(), `"unchanged":3`) || !strings.Contains(rec.Body.String(), `"steps":0`) {
		t.Errorf("plan after apply: %s", rec.Body)
	}
	rec = reqDo(h, pa, "GET", "/api/policy/sod/export", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	rec = reqDo(h, pa, "POST", "/api/policy/sod/plan", req(exp.Files))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"steps":0`) || !strings.Contains(rec.Body.String(), `"created":0`) {
		t.Errorf("round trip plan: %d %s", rec.Code, rec.Body)
	}
	// nothing leaked into the other tenant
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if rs, err := c.SodRulesets(); err != nil || len(rs) != 0 {
			t.Errorf("tenant A got %v, %v", rs, err)
		}
		if refs, err := c.SodPolicyRefs(); err != nil || len(refs) != 0 {
			t.Errorf("tenant A got refs %v, %v", refs, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
