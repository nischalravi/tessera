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

// Roles as code through the API (issue #650, AC-4): export, validate and plan change nothing; an apply is a
// change request that a different admin approves, and approving it applies exactly the plan that was filed.
func TestPolicyRolesAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "alice")
	b := f.B.IDs

	// an existing role, made the UI way, is exported with its key
	body := fmt.Sprintf(`{"name":"Engineer","risk":"medium","requestable":true,"birthright":{"department":["Engineering"]},
		"entitlement_group_ids":[%d,%d]}`, b["group:okta:eng"], b["group:okta:platform"])
	if rec := reqDo(h, pa, "POST", "/api/roles", body); rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, viewer, "POST", "/api/policy/roles/plan", `{"files":{}}`); rec.Code != 403 {
		t.Errorf("a viewer planned: %d", rec.Code)
	}
	rec := reqDo(h, pa, "GET", "/api/policy/roles/export", "")
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
	if exp.Tenant != f.B.Slug || exp.Files["roles/engineer.yaml"] == "" || !strings.Contains(exp.Files["birthright/engineer.cedar"], `"Engineering"`) || len(exp.Digest) != 64 {
		t.Fatalf("export = %+v", exp)
	}
	// the export plans as no change
	req := func(files map[string]string) string {
		raw, _ := json.Marshal(map[string]any{"commit": "c0ffee", "files": files})
		return string(raw)
	}
	rec = reqDo(h, pa, "POST", "/api/policy/roles/plan", req(exp.Files))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"roles_unchanged":1`) || !strings.Contains(rec.Body.String(), `"roles_created":0`) {
		t.Fatalf("round trip plan: %d %s", rec.Code, rec.Body)
	}

	// a new role in the bundle
	files := map[string]string{}
	for k, v := range exp.Files {
		files[k] = v
	}
	files["roles/support.yaml"] = fmt.Sprintf("schema: tessera.role/v1\nkey: support\nname: Support\nrisk: low\nentitlements: [okta:%s]\n", groupName(t, f, "group:okta:payments-clerks"))
	rec = reqDo(h, pa, "POST", "/api/policy/roles/plan", req(files))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"roles_created":1`) || !strings.Contains(rec.Body.String(), `"plan_sha256":"`) {
		t.Fatalf("plan: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, pa, "POST", "/api/policy/roles/validate", req(files)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"valid":true`) {
		t.Errorf("validate: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, pa, "GET", "/api/roles", ""); strings.Contains(rec.Body.String(), "Support") {
		t.Fatalf("a plan saved a role: %s", rec.Body)
	}

	// findings come back together, with path and code
	bad := map[string]string{"tessera.yaml": strings.Replace(exp.Files["tessera.yaml"], f.B.Slug, "globex", 1),
		"roles/support.yaml": strings.Replace(files["roles/support.yaml"], "okta:", "nowhere:", 1)}
	rec = reqDo(h, pa, "POST", "/api/policy/roles/plan", req(bad))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"invalid_bundle"`) || !strings.Contains(rec.Body.String(), `"tenant_mismatch"`) ||
		!strings.Contains(rec.Body.String(), `"unknown_entitlement"`) || !strings.Contains(rec.Body.String(), `"path":"roles/support.yaml"`) {
		t.Errorf("invalid bundle: %d %s", rec.Code, rec.Body)
	}
	// a body that is not JSON of that shape, and a file that is too long, are refused at the boundary
	if rec := reqDo(h, pa, "POST", "/api/policy/roles/plan", `{"files":["x"]}`); rec.Code != 422 && rec.Code != 400 {
		t.Errorf("malformed body: %d", rec.Code)
	}
	huge := map[string]string{"tessera.yaml": exp.Files["tessera.yaml"], "roles/x.yaml": strings.Repeat("a", 300<<10)}
	if rec := reqDo(h, pa, "POST", "/api/policy/roles/plan", req(huge)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "too_large") {
		t.Errorf("an oversized file: %d %.200s", rec.Code, rec.Body)
	}

	// applying files a change request; the filer cannot approve it, a different admin does
	ta1 := reqLogin(t, f, "ta1@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	ta2 := reqLogin(t, f, "ta2@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	if rec := reqDo(h, pa, "POST", "/api/policy/roles/apply", req(files)); rec.Code != 403 {
		t.Errorf("a policy admin filed an apply: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, ta1, "POST", "/api/policy/roles/apply", req(files))
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
		Plan struct {
			PlanSHA256 string `json:"plan_sha256"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &filed); err != nil {
		t.Fatal(err)
	}
	if filed.Change.Type != "roles.bundle.apply" || !filed.Change.TwoPerson || filed.Change.Status != "pending_approval" || len(filed.Plan.PlanSHA256) != 64 {
		t.Fatalf("filed = %s", rec.Body)
	}
	if rec := reqDo(h, pa, "GET", "/api/roles", ""); strings.Contains(rec.Body.String(), "Support") {
		t.Fatalf("a request applied before its approval: %s", rec.Body)
	}
	approve := fmt.Sprintf(`{"payload_hash":%q}`, filed.Change.PayloadHash)
	if rec := reqDo(h, ta1, "POST", "/api/admin/change-requests/"+filed.Change.ID+"/approve", approve); rec.Code != 403 {
		t.Errorf("self-approval: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, ta2, "POST", "/api/admin/change-requests/"+filed.Change.ID+"/approve", approve); rec.Code != 200 {
		t.Fatalf("approval: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, pa, "GET", "/api/roles", ""); !strings.Contains(rec.Body.String(), "Support") {
		t.Fatalf("the approved bundle was not applied: %s", rec.Body)
	}
	err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		r, err := c.BusinessRoleByKey("support")
		if err != nil {
			return err
		}
		vs, err := c.RoleVersions(r.ID)
		if err != nil || len(vs) != 1 || vs[0].PolicyRef == nil || !strings.Contains(*vs[0].PolicyRef, `"commit":"c0ffee"`) {
			t.Errorf("versions = %v, %v; want one with the commit as its policy_ref", vs, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the same bundle again plans as no change
	rec = reqDo(h, pa, "POST", "/api/policy/roles/plan", req(files))
	if !strings.Contains(rec.Body.String(), `"roles_unchanged":2`) {
		t.Errorf("plan after apply: %s", rec.Body)
	}
	// nothing leaked into the other tenant
	err = f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if _, err := c.BusinessRoleByKey("support"); err == nil {
			t.Error("tenant A got tenant B's role")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// groupName is the name of a fixture group of tenant B.
func groupName(t *testing.T, f *storetest.Fixture, key string) string {
	t.Helper()
	var name string
	err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		gs, err := c.Groups()
		for _, g := range gs {
			if g.ID == f.B.IDs[key] {
				name = g.Name
			}
		}
		return err
	})
	if err != nil || name == "" {
		t.Fatalf("group %s: %q, %v", key, name, err)
	}
	return name
}
