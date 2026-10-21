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

// The workflow designer (issue #298): who manages workflows, that definitions are validated
// (whatever the client sends), versioning, assignment, that a workflow routes a request, and
// that tenants do not see each other's.

const decideOnly = `[{"id":"d","type":"approval","approver":"decider"}]`

func TestWorkflowsAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	auditor := reqLogin(t, f, "au@b.example", []auth.Role{auth.RoleAuditor}, "")
	call := func(l authtest.Login, method, path, body string, want int) map[string]any {
		t.Helper()
		rec := reqDo(h, l, method, path, body)
		if rec.Code != want {
			t.Fatalf("%s %s: %d (want %d) %s", method, path, rec.Code, want, rec.Body)
		}
		if strings.HasPrefix(rec.Body.String(), "{") {
			return jsonMap(t, rec.Body.String())
		}
		return nil
	}

	// everyone who reads the graph reads workflows and the editor's vocabulary; only workflows.manage writes
	list := call(alice, "GET", "/api/workflows", "", 200)
	if list["can_manage"] != false || len(list["step_types"].([]any)) != 6 || list["workflows"] == nil {
		t.Errorf("list for a viewer: %v", list)
	}
	if call(admin, "GET", "/api/workflows", "", 200)["can_manage"] != true {
		t.Error("a policy admin cannot manage")
	}
	for _, l := range []authtest.Login{alice, auditor} {
		call(l, "POST", "/api/workflows", `{"name":"x","scope":"access","steps":`+decideOnly+`}`, 403)
		call(l, "POST", "/api/workflows/validate", `{"scope":"access","steps":`+decideOnly+`}`, 403)
	}

	// definitions are validated: every issue comes back
	bad := call(admin, "POST", "/api/workflows", `{"name":"loop","scope":"access","steps":[
		{"id":"a","type":"approval","approver":"manager"},{"id":"b","type":"approval","approver":"decider","next":"a"}]}`, 422)
	if bad["error"] != "invalid_workflow" || bad["issues"].([]any)[0].(map[string]any)["code"] != "cycle" {
		t.Errorf("a cycle: %v", bad)
	}
	call(admin, "POST", "/api/workflows", `{"name":"x","scope":"access","steps":[]}`, 422)
	call(admin, "POST", "/api/workflows", `{"name":"","scope":"access","steps":`+decideOnly+`}`, 422)
	call(admin, "POST", "/api/workflows", `{"name":"x","scope":"galaxy","steps":`+decideOnly+`}`, 422)
	call(admin, "POST", "/api/workflows", `{"name":"x","scope":"access","steps":`+decideOnly+`,"surprise":1}`, 422)
	call(admin, "POST", "/api/workflows", `{"name":"x","scope":"access","steps":[{"id":"d","type":"approval","approver":"decider","surprise":1}]}`, 422)
	call(admin, "POST", "/api/workflows", `{"name":"x","scope":"access","steps":[{"id":"q","type":"questionnaire","questionnaire_id":"nope"},
		{"id":"d","type":"approval","approver":"decider"}]}`, 422)
	call(admin, "POST", "/api/workflows", `{"name":"x","scope":"access","steps":[{"id":"g","type":"approval","approver":"group","group_id":"nope"}]}`, 422)
	v := call(admin, "POST", "/api/workflows/validate", `{"scope":"access","steps":[{"id":"n","type":"notify","notify":"requester"}]}`, 200)
	if v["valid"] != false || v["issues"].([]any)[0].(map[string]any)["code"] != "no_approval" {
		t.Errorf("validate: %v", v)
	}
	if v := call(admin, "POST", "/api/workflows/validate", `{"scope":"access","steps":`+decideOnly+`}`, 200); v["valid"] != true || len(v["issues"].([]any)) != 0 {
		t.Errorf("validate a good one: %v", v)
	}

	created := call(admin, "POST", "/api/workflows", `{"name":"Decider only","description":"Fast lane","scope":"access","steps":`+decideOnly+`}`, 201)
	id := created["id"].(string)
	if created["version"].(float64) != 1 || created["status"] != "active" || created["scope"] != "access" || len(created["steps"].([]any)) != 1 || len(created["targets"].([]any)) != 0 {
		t.Fatalf("created: %v", created)
	}
	call(admin, "POST", "/api/workflows", `{"name":"decider only","scope":"access","steps":`+decideOnly+`}`, 409) // same name

	// a new version replaces the steps; a stale editor is refused
	call(admin, "PUT", "/api/workflows/"+id, `{"version":1,"name":"Decider only","steps":[{"id":"m","type":"approval","approver":"manager"},
		{"id":"d","type":"approval","approver":"decider"}]}`, 200)
	call(admin, "PUT", "/api/workflows/"+id, `{"version":1,"name":"stale","steps":`+decideOnly+`}`, 409)
	call(alice, "PUT", "/api/workflows/"+id, `{"version":2,"name":"x","steps":`+decideOnly+`}`, 403)
	detail := call(alice, "GET", "/api/workflows/"+id, "", 200)
	if detail["version"].(float64) != 2 || len(detail["steps"].([]any)) != 2 || len(detail["versions"].([]any)) != 2 ||
		detail["versions"].([]any)[1].(map[string]any)["version"].(float64) != 1 {
		t.Fatalf("detail: %v", detail)
	}
	call(alice, "GET", "/api/workflows/00000000-0000-4000-8000-00000000dead", "", 404)
	call(alice, "GET", "/api/workflows/not-a-uuid", "", 404)

	// assignment: items and request types of its scope only; one workflow per target
	call(admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", f.B.IDs["group:okta:platform"]), `{"requestable":true,"risk":"medium"}`, 200)
	itemID := call(alice, "GET", "/api/catalog", "", 200)["items"].([]any)[0].(map[string]any)["id"].(string)
	assign := func(id, targets string, want int) map[string]any {
		t.Helper()
		return call(admin, "PUT", "/api/workflows/"+id+"/assignments", `{"targets":`+targets+`}`, want)
	}
	assign(id, `[{"kind":"catalog_item","target_id":"00000000-0000-4000-8000-00000000dead"}]`, 404)
	assign(id, `[{"kind":"request_type","target_id":"service_account_create"}]`, 422)
	assign(id, `[{"kind":"everything","target_id":"x"}]`, 422)
	got := assign(id, fmt.Sprintf(`[{"kind":"catalog_item","target_id":%q},{"kind":"request_type","target_id":"access"}]`, itemID), 200)
	if len(got["targets"].([]any)) != 2 {
		t.Fatalf("targets: %v", got)
	}
	other := call(admin, "POST", "/api/workflows", `{"name":"Other","scope":"access","steps":`+decideOnly+`}`, 201)["id"].(string)
	assign(other, `[{"kind":"request_type","target_id":"access"}]`, 409)
	call(alice, "PUT", "/api/workflows/"+id+"/assignments", `{"targets":[]}`, 403)
	// a service-account workflow takes service-account request types, and a transfer needs both owners
	sa := call(admin, "POST", "/api/workflows", `{"name":"SA","scope":"service_account","steps":[{"id":"o","type":"approval","approver":"old_owner"},{"id":"d","type":"approval","approver":"decider"}]}`, 201)["id"].(string)
	assign(sa, `[{"kind":"request_type","target_id":"service_account_transfer"}]`, 422)
	assign(sa, fmt.Sprintf(`[{"kind":"catalog_item","target_id":%q}]`, itemID), 422)
	assign(sa, `[{"kind":"request_type","target_id":"service_account_change"}]`, 200)

	// the workflow now routes the item: manager (carol), then a decider; the policy's stages are not used
	rec := reqDo(h, alice, "POST", "/api/requests", fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":[%q],"justification":"Atlas"}`, f.B.IDs["alice"], itemID))
	if rec.Code != 201 {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	line := jsonMap(t, rec.Body.String())["lines"].([]any)[0].(map[string]any)
	stages := line["stages"].([]any)
	if len(stages) != 2 || stages[0].(map[string]any)["kind"] != "manager" || stages[1].(map[string]any)["kind"] != "decider" ||
		stages[0].(map[string]any)["label"] != "Manager approval" {
		t.Fatalf("stages: %v", stages)
	}
	if wf := line["workflow"].(map[string]any); wf["id"] != id || wf["version"].(float64) != 2 || wf["name"] != "Decider only" {
		t.Errorf("workflow of the line: %v", wf)
	}
	if d := call(admin, "GET", "/api/workflows/"+id, "", 200); d["runs"].(float64) != 1 {
		t.Errorf("runs = %v", d["runs"])
	}

	// retiring stops it routing; its targets go back to the item's policy; its runs stay
	retired := call(admin, "POST", "/api/workflows/"+id+"/retire", `{}`, 200)
	if retired["status"] != "retired" || len(retired["targets"].([]any)) != 0 {
		t.Errorf("retired: %v", retired)
	}
	call(admin, "POST", "/api/workflows/"+id+"/retire", `{}`, 409)
	call(admin, "PUT", "/api/workflows/"+id, `{"version":2,"name":"x","steps":`+decideOnly+`}`, 409)
	assign(id, `[]`, 409)
	assign(other, `[{"kind":"request_type","target_id":"access"}]`, 200) // free again
	if d := call(alice, "GET", "/api/workflows/"+id, "", 200); d["runs"].(float64) != 1 {
		t.Errorf("a retired workflow lost its runs: %v", d["runs"])
	}

	actions := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"workflow.create", "workflow.update", "workflow.assign", "workflow.retire"} {
		if actions[a] == 0 {
			t.Errorf("no %s audit event (have %v)", a, actions)
		}
	}
}

// Changing a workflow needs a fresh phishing-resistant sign-in.
func TestWorkflowsAPI_StepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/workflows", `{"name":"x","scope":"access","steps":` + decideOnly + `}`},
		{"PUT", "/api/workflows/00000000-0000-4000-8000-00000000dead", `{"version":1,"name":"x","steps":` + decideOnly + `}`},
		{"POST", "/api/workflows/00000000-0000-4000-8000-00000000dead/retire", `{}`},
		{"PUT", "/api/workflows/00000000-0000-4000-8000-00000000dead/assignments", `{"targets":[]}`},
	} {
		if rec := reqDo(h, stale, c.method, c.path, c.body); rec.Code != 401 && rec.Code != 403 {
			t.Errorf("%s %s with a stale sign-in: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
}

func TestWorkflowsAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	adminB := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	adminA := signInA(t, f, auth.RolePolicyAdmin)
	rec := reqDo(h, adminA, "POST", "/api/workflows", `{"name":"A only","scope":"access","steps":`+decideOnly+`}`)
	if rec.Code != 201 {
		t.Fatalf("create in A: %d %s", rec.Code, rec.Body)
	}
	idA := jsonMap(t, rec.Body.String())["id"].(string)
	if rec := reqDo(h, adminB, "GET", "/api/workflows", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), "A only") || strings.Contains(rec.Body.String(), idA) {
		t.Errorf("B lists A's: %d %s", rec.Code, rec.Body)
	}
	for _, c := range []struct{ method, suffix, body string }{
		{"GET", "", ""}, {"PUT", "", `{"version":1,"name":"x","steps":` + decideOnly + `}`},
		{"POST", "/retire", `{}`}, {"PUT", "/assignments", `{"targets":[{"kind":"request_type","target_id":"access"}]}`},
	} {
		cross := reqDo(h, adminB, c.method, "/api/workflows/"+idA+c.suffix, c.body)
		if cross.Code != 404 || strings.Contains(cross.Body.String(), "A only") || strings.Contains(cross.Body.String(), idA) {
			t.Errorf("%s %s: %d %s", c.method, c.suffix, cross.Code, cross.Body)
		}
	}
	// B's own workflow with the same name and target is fine
	if rec := reqDo(h, adminB, "POST", "/api/workflows", `{"name":"A only","scope":"access","steps":`+decideOnly+`}`); rec.Code != 201 {
		t.Errorf("same name in B: %d %s", rec.Code, rec.Body)
	}
}
