package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Agent scopes as code through the API (issue #653, AC-7): export, validate and plan change nothing; an apply is a
// change request that a different admin approves, approving it applies exactly the plan that was filed, and the
// applied scope turns up as findings on /api/violations.
func TestPolicyAgentsAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	// B has discovered an agent (its identity is a person of the fixture, which holds permissions); A has one B cannot name
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.UpsertAgentProfile(&store.AgentProfile{Source: "entra", ExternalID: "hb", IdentityID: f.B.IDs["alice"], Kind: "agent"}, storetest.Now)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.UpsertAgentProfile(&store.AgentProfile{Source: "entra", ExternalID: "only-a", IdentityID: f.A.IDs["alice"], Kind: "agent"}, storetest.Now)
	})
	if err != nil {
		t.Fatal(err)
	}
	h := newIsolationServer(f).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "alice")
	ta1 := reqLogin(t, f, "ta1@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	ta2 := reqLogin(t, f, "ta2@b.example", []auth.Role{auth.RoleTenantAdmin}, "")

	if rec := reqDo(h, viewer, "POST", "/api/policy/agents/plan", `{"files":{}}`); rec.Code != 403 {
		t.Errorf("a viewer planned: %d", rec.Code)
	}
	rec := reqDo(h, pa, "GET", "/api/policy/agents/export", "")
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
	if exp.Tenant != f.B.Slug || !strings.Contains(exp.Files["tessera.yaml"], "agents: partial") || len(exp.Digest) != 64 {
		t.Fatalf("export = %+v", exp)
	}
	req := func(files map[string]string) string {
		raw, _ := json.Marshal(map[string]any{"commit": "c0ffee", "files": files})
		return string(raw)
	}
	// a scope no permission of the agent can satisfy: it may only write in a system that does not exist
	doc := `schema: tessera.agentscope/v1
key: hb
name: Helper bot
agent:
  source: entra
  external_id: hb
allow:
  actions: [write]
  resources:
    - systems: [nowhere]
`
	files := map[string]string{
		"tessera.yaml":   fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n  agents: partial\n", f.B.Slug),
		"agents/hb.yaml": doc,
	}
	rec = reqDo(h, pa, "POST", "/api/policy/agents/plan", req(files))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"created":1`) || !strings.Contains(rec.Body.String(), `"plan_sha256":"`) {
		t.Fatalf("plan: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, pa, "POST", "/api/policy/agents/validate", req(files)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"valid":true`) {
		t.Errorf("validate: %d %s", rec.Code, rec.Body)
	}
	// findings come back together, with path and code
	bad := map[string]string{"tessera.yaml": files["tessera.yaml"], "agents/hb.yaml": strings.Replace(doc, "[write]", "[write, root]", 1)}
	rec = reqDo(h, pa, "POST", "/api/policy/agents/plan", req(bad))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"invalid_bundle"`) || !strings.Contains(rec.Body.String(), `"invalid_actions"`) || !strings.Contains(rec.Body.String(), `"path":"agents/hb.yaml"`) {
		t.Errorf("invalid bundle: %d %s", rec.Code, rec.Body)
	}
	// a selector naming another tenant's agent, and another tenant's bundle, are refused
	foreign := map[string]string{"tessera.yaml": files["tessera.yaml"], "agents/hb.yaml": strings.Replace(doc, "external_id: hb", "external_id: only-a", 1)}
	if rec := reqDo(h, pa, "POST", "/api/policy/agents/plan", req(foreign)); rec.Code != 422 || !strings.Contains(rec.Body.String(), `"unknown_agent"`) {
		t.Errorf("another tenant's agent: %d %s", rec.Code, rec.Body)
	}
	other := map[string]string{"tessera.yaml": strings.Replace(files["tessera.yaml"], f.B.Slug, "globex", 1), "agents/hb.yaml": doc}
	if rec := reqDo(h, pa, "POST", "/api/policy/agents/plan", req(other)); rec.Code != 422 || !strings.Contains(rec.Body.String(), `"tenant_mismatch"`) {
		t.Errorf("another tenant's bundle: %d %s", rec.Code, rec.Body)
	}
	huge := map[string]string{"tessera.yaml": files["tessera.yaml"], "agents/x.yaml": strings.Repeat("a", 300<<10)}
	if rec := reqDo(h, pa, "POST", "/api/policy/agents/plan", req(huge)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "too_large") {
		t.Errorf("an oversized file: %d %.200s", rec.Code, rec.Body)
	}

	violations := func() string {
		rec := reqDo(h, pa, "GET", "/api/violations", "")
		if rec.Code != 200 {
			t.Fatalf("violations: %d %s", rec.Code, rec.Body)
		}
		return rec.Body.String()
	}
	if strings.Contains(violations(), "agent-out-of-scope") {
		t.Fatal("a finding before any scope was applied")
	}

	// applying files a change request; a policy admin cannot file one, the filer cannot approve it
	if rec := reqDo(h, pa, "POST", "/api/policy/agents/apply", req(files)); rec.Code != 403 {
		t.Errorf("a policy admin filed an apply: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, ta1, "POST", "/api/policy/agents/apply", req(files))
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
	if filed.Change.Type != "agent_scopes.bundle.apply" || !filed.Change.TwoPerson || filed.Change.Status != "pending_approval" {
		t.Fatalf("filed = %s", rec.Body)
	}
	count := func(tenant storetest.Tenant) int {
		n := 0
		err := f.DB.ReadTenant(context.Background(), tenant.ID, func(c *store.TenantTx) error {
			ss, err := c.AgentScopes()
			n = len(ss)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(f.B) != 0 || strings.Contains(violations(), "agent-out-of-scope") {
		t.Fatal("a request applied before its approval")
	}
	approve := fmt.Sprintf(`{"payload_hash":%q}`, filed.Change.PayloadHash)
	if rec := reqDo(h, ta1, "POST", "/api/admin/change-requests/"+filed.Change.ID+"/approve", approve); rec.Code != 403 {
		t.Errorf("self-approval: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, ta2, "POST", "/api/admin/change-requests/"+filed.Change.ID+"/approve", approve); rec.Code != 200 {
		t.Fatalf("approval: %d %s", rec.Code, rec.Body)
	}
	if count(f.B) != 1 || count(f.A) != 0 {
		t.Fatalf("scopes after the approval: B %d, A %d; want 1 and 0", count(f.B), count(f.A))
	}
	// the applied scope is an invariant: the agent's permissions are out of scope, on /api/violations
	if v := violations(); !strings.Contains(v, `"policy_id":"agent-out-of-scope"`) || !strings.Contains(v, `"key":"hb:`) {
		t.Errorf("no out-of-scope finding after the apply: %.600s", v)
	}
	// the same bundle again plans as no change, and the export of the result is that bundle
	rec = reqDo(h, pa, "POST", "/api/policy/agents/plan", req(files))
	if !strings.Contains(rec.Body.String(), `"unchanged":1`) || !strings.Contains(rec.Body.String(), `"steps":0`) {
		t.Errorf("plan after apply: %s", rec.Body)
	}
	rec = reqDo(h, pa, "GET", "/api/policy/agents/export", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	rec = reqDo(h, pa, "POST", "/api/policy/agents/plan", req(exp.Files))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"steps":0`) || !strings.Contains(rec.Body.String(), `"created":0`) {
		t.Errorf("round trip plan: %d %s", rec.Code, rec.Body)
	}
	// tenant A sees no finding of B's scope
	paA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	rec = reqDo(h, paA, "GET", "/api/violations", "")
	if strings.Contains(rec.Body.String(), "agent-out-of-scope") {
		t.Errorf("tenant A sees B's scope: %.300s", rec.Body)
	}
}

// A whitespace-only commit is refused when the apply is filed, not after a second admin approved it (issue #759):
// the apply trims the commit and refuses an empty one, so filing it made a request that could never succeed.
func TestPolicyBundleApply_BlankCommitRefusedAtFiling(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	pa := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	ta1 := reqLogin(t, f, "ta1@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	for _, kind := range []string{"agents", "roles", "jit", "sod"} {
		t.Run(kind, func(t *testing.T) {
			rec := reqDo(h, pa, "GET", "/api/policy/"+kind+"/export", "")
			if rec.Code != 200 {
				t.Fatalf("export: %d %s", rec.Code, rec.Body)
			}
			var exp struct {
				Files map[string]string `json:"files"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
				t.Fatal(err)
			}
			for _, commit := range []string{" ", " \t\n "} {
				raw, _ := json.Marshal(map[string]any{"commit": commit, "files": exp.Files})
				if rec := reqDo(h, ta1, "POST", "/api/policy/"+kind+"/apply", string(raw)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "commit") {
					t.Errorf("commit %q: %d %s", commit, rec.Code, rec.Body)
				}
			}
		})
	}
}
