package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Access drift routes (issue #301): RBAC, step-up, validation, audit and tenant scoping.
func TestDriftAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	user := func(tenant int, email string, r auth.Role, c authtest.Ctx) authtest.Login {
		id := f.A.ID
		if tenant == 1 {
			id = f.B.ID
		}
		return signIn(t, f.DB, id, authtest.User{Email: email, Roles: []auth.Role{r}}, c, storetest.Now)
	}
	viewer := user(1, "v@b.example", auth.RoleViewer, authtest.Phr)
	op := user(1, "op@b.example", auth.RoleOperator, authtest.Phr)
	pa := user(1, "pa@b.example", auth.RolePolicyAdmin, authtest.Phr)
	paWeak := user(1, "paw@b.example", auth.RolePolicyAdmin, authtest.AAL1)
	ta := user(1, "ta@b.example", auth.RoleTenantAdmin, authtest.Phr)
	paA := user(0, "pa@a.example", auth.RolePolicyAdmin, authtest.Phr)

	if rec := schedDo(h, viewer, "GET", "/api/access-drift", ""); rec.Code != 403 {
		t.Errorf("viewer lists drift: %d", rec.Code)
	}
	for _, l := range []authtest.Login{op, ta, pa} {
		if rec := schedDo(h, l, "GET", "/api/access-drift?class=rogue&status=open", ""); rec.Code != 200 {
			t.Errorf("list: %d %s", rec.Code, rec.Body)
		}
	}
	for _, q := range []string{"class=x", "status=x", "identity_id=0", "limit=0", "limit=501"} {
		if rec := schedDo(h, op, "GET", "/api/access-drift?"+q, ""); rec.Code != 422 {
			t.Errorf("?%s = %d", q, rec.Code)
		}
	}

	// policies: policy admin only; invalid combinations refused
	pol := `{"system":"okta","drift_class":"rogue","action":"owner_task"}`
	if rec := schedDo(h, op, "PUT", "/api/remediation-policies", pol); rec.Code != 403 {
		t.Errorf("operator sets a policy: %d", rec.Code)
	}
	if rec := schedDo(h, ta, "PUT", "/api/remediation-policies", pol); rec.Code != 403 {
		t.Errorf("tenant admin sets a policy: %d", rec.Code)
	}
	if rec := schedDo(h, paWeak, "PUT", "/api/remediation-policies", pol); rec.Code == 200 {
		t.Errorf("a policy without a phishing-resistant sign-in: %d", rec.Code)
	}
	for _, bad := range []string{`{"system":"okta","drift_class":"rogue","action":"auto_provision"}`,
		`{"system":"okta","drift_class":"missing","action":"auto_revoke"}`, `{"system":"","drift_class":"rogue","action":"owner_task"}`,
		`{"system":"okta","drift_class":"nope","action":"owner_task"}`, `{"system":"okta","drift_class":"rogue","action":"x","extra":1}`} {
		if rec := schedDo(h, pa, "PUT", "/api/remediation-policies", bad); rec.Code != 422 {
			t.Errorf("%s = %d", bad, rec.Code)
		}
	}
	rec := schedDo(h, pa, "PUT", "/api/remediation-policies", pol)
	if rec.Code != 200 {
		t.Fatalf("put policy: %d %s", rec.Code, rec.Body)
	}
	var p policyView
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if p.Action != "owner_task" || p.EntitlementRef != "" {
		t.Errorf("policy = %+v", p)
	}
	if rec := schedDo(h, pa, "PUT", "/api/remediation-policies", `{"system":"okta","drift_class":"rogue","action":"auto_revoke"}`); rec.Code != 200 {
		t.Errorf("replace: %d", rec.Code)
	}
	if rec := schedDo(h, op, "GET", "/api/remediation-policies", ""); rec.Code != 200 || strings.Count(rec.Body.String(), `"drift_class"`) != 1 ||
		!strings.Contains(rec.Body.String(), "auto_revoke") {
		t.Errorf("list policies: %d %s", rec.Code, rec.Body)
	}
	// another tenant cannot see or delete it
	if rec := schedDo(h, paA, "DELETE", "/api/remediation-policies/"+p.ID, ""); rec.Code != 404 {
		t.Errorf("A deletes B's policy: %d", rec.Code)
	}
	if rec := schedDo(h, paA, "GET", "/api/remediation-policies", ""); strings.Contains(rec.Body.String(), p.ID) {
		t.Error("A lists B's policy")
	}

	// run the engine; the fixture's JIT intents are not seen by the connector: drift appears
	rec = schedDo(h, pa, "POST", "/api/access-drift/run", "")
	if rec.Code != 200 {
		t.Fatalf("run: %d %s", rec.Code, rec.Body)
	}
	rec = schedDo(h, op, "GET", "/api/access-drift?limit=500", "")
	var list struct {
		Items []driftView `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) == 0 {
		t.Fatalf("no drift after a run: %s", rec.Body)
	}
	id := list.Items[0].ID
	if rec := schedDo(h, op, "POST", "/api/access-drift/"+id+"/accept", `{"reason":"x"}`); rec.Code != 403 {
		t.Errorf("operator accepts: %d", rec.Code)
	}
	if rec := schedDo(h, paWeak, "POST", "/api/access-drift/"+id+"/accept", `{"reason":"x"}`); rec.Code == 200 {
		t.Errorf("accept without step-up: %d", rec.Code)
	}
	if rec := schedDo(h, pa, "POST", "/api/access-drift/"+id+"/accept", `{"reason":""}`); rec.Code != 422 {
		t.Errorf("accept without a reason: %d %s", rec.Code, rec.Body)
	}
	if rec := schedDo(h, pa, "POST", "/api/access-drift/"+id+"/remediate", `{"action":"bogus"}`); rec.Code != 422 {
		t.Errorf("bogus action: %d", rec.Code)
	}
	if rec := schedDo(h, paA, "POST", "/api/access-drift/"+id+"/accept", `{"reason":"x"}`); rec.Code != 404 {
		t.Errorf("A accepts B's drift: %d", rec.Code)
	}
	if rec := schedDo(h, paA, "POST", "/api/access-drift/"+id+"/remediate", `{"action":"owner_task"}`); rec.Code != 404 {
		t.Errorf("A remediates B's drift: %d", rec.Code)
	}
	if rec := schedDo(h, pa, "POST", "/api/access-drift/"+id+"/accept", `{"reason":"known exception"}`); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"status":"accepted"`) {
		t.Errorf("accept: %d %s", rec.Code, rec.Body)
	}
	acts := reviewAudit(t, f)
	if acts["drift.policy_set"] != 2 || acts["drift.accept"] != 1 || acts["drift.run"] != 1 {
		t.Errorf("audit %v", acts)
	}
	if rec := schedDo(h, pa, "DELETE", "/api/remediation-policies/"+p.ID, ""); rec.Code != 200 {
		t.Errorf("delete policy: %d", rec.Code)
	}
}
