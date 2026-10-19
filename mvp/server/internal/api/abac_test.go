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
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

const engCond = `{"attr":"identity.department","op":"eq","value":"Engineering"}`

func TestAbacAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	b := f.B.IDs

	create := fmt.Sprintf(`{"name":"Engineers","description":"dept","condition":%s,"note":"first"}`, engCond)
	if rec := reqDo(h, viewer, "POST", "/api/abac/policies", create); rec.Code != 403 {
		t.Errorf("viewer create: %d", rec.Code)
	}
	for body, code := range map[string]string{
		`{"name":"x","condition":{"attr":"identity.department","op":"matches","value":"x"}}`: "invalid_condition",
		`{"name":"x","condition":{"attr":"nope","op":"eq","value":"x"}}`:                     "invalid_condition",
		`{"name":"x","condition":{"all":[]}}`:                                                "invalid_condition",
		`{"name":"x","condition":{"attr":"identity.title","op":"eq","value":"x","extra":1}}`: "invalid_condition",
		`{"name":"x"}`: "invalid_condition",
		`{"name":"","condition":` + engCond + `}`: "invalid_name",
	} {
		if rec := reqDo(h, admin, "POST", "/api/abac/policies", body); rec.Code != 422 || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
	rec := reqDo(h, admin, "POST", "/api/abac/policies", create)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var pv abacPolicyViewT
	_ = json.Unmarshal(rec.Body.Bytes(), &pv)
	id := pv.ID
	if rec := reqDo(h, admin, "POST", "/api/abac/policies", create); rec.Code != 409 {
		t.Errorf("duplicate name: %d", rec.Code)
	}

	// simulate: the saved version matches people; a draft that matches nobody loses them all
	rec = reqDo(h, admin, "POST", "/api/abac/simulate", fmt.Sprintf(`{"policy_id":"%s","condition":{"attr":"identity.department","op":"eq","value":"Nowhere"}}`, id))
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	num := func(k string) int { v, _ := raw[k].(float64); return int(v) }
	if rec.Code != 200 || num("before") < 1 || num("lose_count") != num("before") || num("gain_count") != 0 || num("matching") != 0 {
		t.Fatalf("simulate: %d %s", rec.Code, rec.Body)
	}
	// a draft testing an attribute nobody has: nobody matches, all unknown
	rec = reqDo(h, admin, "POST", "/api/abac/simulate", `{"condition":{"attr":"identity.clearance","op":"eq","value":"x"}}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"matching":0`) || strings.Contains(rec.Body.String(), `"missing_attributes":0`) {
		t.Errorf("simulate missing attribute: %d %s", rec.Code, rec.Body)
	}
	// resource and context attributes are accepted; others are refused
	rec = reqDo(h, admin, "POST", "/api/abac/simulate",
		`{"condition":{"all":[{"attr":"context.aal","op":"gte","value":2},{"attr":"resource.risk","op":"eq","value":"high"}]},"resource":{"resource.risk":"high"},"context":{"context.aal":2}}`)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `"matching":0`) {
		t.Errorf("simulate with context: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/abac/simulate", `{"condition":`+engCond+`,"resource":{"identity.type":"x"}}`); rec.Code != 422 {
		t.Errorf("simulate bad attribute namespace: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, viewer, "POST", "/api/abac/simulate", `{"condition":`+engCond+`}`); rec.Code != 200 {
		t.Errorf("viewer simulate: %d", rec.Code)
	}

	// version 2, stale version refused, versions kept
	upd := fmt.Sprintf(`{"version":%%d,"name":"Engineers","condition":{"any":[%s,{"attr":"identity.type","op":"eq","value":"service"}]},"note":"widen"}`, engCond)
	if rec := reqDo(h, admin, "PUT", "/api/abac/policies/"+id, fmt.Sprintf(upd, 7)); rec.Code != 409 {
		t.Errorf("stale update: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "PUT", "/api/abac/policies/"+id, fmt.Sprintf(upd, 1)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"version":2`) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, viewer, "GET", "/api/abac/policies/"+id, "")
	if !strings.Contains(rec.Body.String(), `"note":"first"`) || !strings.Contains(rec.Body.String(), `"note":"widen"`) {
		t.Errorf("versions: %s", rec.Body)
	}

	// birthright: a role whose rule names the policy gets the matching people; a missing policy is refused
	roleBody := func(policy string) string {
		return fmt.Sprintf(`{"name":"Eng via policy","risk":"low","birthright":{"policy":"%s"},"entitlement_group_ids":[%d]}`,
			policy, b["group:okta:platform"])
	}
	if rec := reqDo(h, admin, "POST", "/api/roles", roleBody("00000000-0000-4000-8000-00000000dead")); rec.Code != 422 {
		t.Errorf("unknown policy in a rule: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "POST", "/api/roles", roleBody(id))
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"policy":"`+id+`"`) || strings.Contains(rec.Body.String(), `"member_count":0`) {
		t.Fatalf("role with a policy rule: %d %s", rec.Code, rec.Body)
	}
	// in use: cannot be retired
	if rec := reqDo(h, admin, "POST", "/api/abac/policies/"+id+"/retire", `{"reason":"x"}`); rec.Code != 409 || !strings.Contains(rec.Body.String(), "policy_in_use") {
		t.Errorf("retire in use: %d %s", rec.Code, rec.Body)
	}

	// catalog eligibility: bind a policy nobody satisfies, then one everybody does
	gid := b["group:okta:payments-clerks"]
	if rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", gid), `{"requestable":true,"risk":"low"}`); rec.Code != 200 {
		t.Fatalf("catalog put: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "POST", "/api/abac/policies", `{"name":"Nobody","condition":{"attr":"identity.department","op":"eq","value":"Nowhere"}}`)
	var nobody abacPolicyViewT
	_ = json.Unmarshal(rec.Body.Bytes(), &nobody)
	submit := fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":["%%s"],"justification":"need it"}`, b["alice"])
	rec = reqDo(h, admin, "GET", "/api/catalog?all=1", "")
	var cat struct {
		Items []struct {
			ID    *string `json:"id"`
			Group struct {
				ID int64 `json:"id"`
			} `json:"group"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &cat)
	var item string
	for _, it := range cat.Items {
		if it.Group.ID == gid && it.ID != nil {
			item = *it.ID
		}
	}
	if item == "" {
		t.Fatalf("no catalog item: %s", rec.Body)
	}
	if rec := reqDo(h, viewer, "PUT", fmt.Sprintf("/api/catalog/items/%d/policy", gid), `{"policy_id":"`+nobody.ID+`"}`); rec.Code != 403 {
		t.Errorf("viewer binds: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d/policy", gid), `{"policy_id":"`+nobody.ID+`"}`); rec.Code != 200 {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "GET", "/api/abac/bindings", ""); !strings.Contains(rec.Body.String(), nobody.ID) {
		t.Errorf("bindings: %s", rec.Body)
	}
	rec = reqDo(h, viewer, "POST", "/api/requests", fmt.Sprintf(submit, item))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "not_eligible") || !strings.Contains(rec.Body.String(), "attribute policy") {
		t.Errorf("request under an unsatisfied policy: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d/policy", gid), `{"policy_id":"`+id+`"}`); rec.Code != 200 {
		t.Fatalf("rebind: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, viewer, "POST", "/api/requests", fmt.Sprintf(submit, item))
	if rec.Code != 201 {
		t.Errorf("request under a satisfied policy: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d/policy", gid), `{"policy_id":null}`); rec.Code != 200 {
		t.Errorf("unbind: %d %s", rec.Code, rec.Body)
	}
	// the unused policy retires, and cannot be bound or edited afterwards
	if rec := reqDo(h, admin, "POST", "/api/abac/policies/"+nobody.ID+"/retire", `{"reason":"unused"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"retired"`) {
		t.Errorf("retire: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d/policy", gid), `{"policy_id":"`+nobody.ID+`"}`); rec.Code != 409 {
		t.Errorf("bind retired: %d", rec.Code)
	}

	acts := reqAuditActions(t, f, f.B.ID)
	for a, n := range map[string]int{"abac.policy.create": 2, "abac.policy.update": 1, "abac.policy.retire": 1,
		"abac.binding.put": 2, "abac.binding.remove": 1} {
		if acts[a] != n {
			t.Errorf("audit %s = %d, want %d", a, acts[a], n)
		}
	}
}

type abacPolicyViewT struct {
	ID string `json:"id"`
}

func TestAbacAPI_RBAC(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	for _, c := range []struct {
		role         auth.Role
		read, manage int
	}{
		{auth.RoleViewer, 200, 403}, {auth.RoleOperator, 200, 403}, {auth.RoleAuditor, 200, 403},
		{auth.RoleTenantAdmin, 200, 403}, {auth.RolePolicyAdmin, 200, 201}, {auth.RoleBreakGlass, 403, 403},
	} {
		l := reqLogin(t, f, string(c.role)+"@b.example", []auth.Role{c.role}, "")
		if rec := reqDo(h, l, "GET", "/api/abac/policies", ""); rec.Code != c.read {
			t.Errorf("%s list: %d", c.role, rec.Code)
		}
		body := fmt.Sprintf(`{"name":"p-%s","condition":%s}`, c.role, engCond)
		if rec := reqDo(h, l, "POST", "/api/abac/policies", body); rec.Code != c.manage {
			t.Errorf("%s create: %d %s", c.role, rec.Code, rec.Body)
		}
	}
}

func seedAbac(t *testing.T, f *storetest.Fixture) map[tenancy.ID]string {
	t.Helper()
	out := map[tenancy.ID]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		name := "Policy " + tn.Slug
		if tn.ID == f.A.ID {
			name += " " + storetest.Sentinel
		}
		id := "pol-" + tn.Slug
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.InsertAbacPolicy(&store.AbacPolicy{ID: id, Name: name, Description: name, Condition: engCond,
				Status: store.AbacActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			return c.AddAbacPolicyVersion(&store.AbacPolicyVersion{PolicyID: id, Version: 1, Snapshot: `{"name":"` + name + `"}`,
				Actor: "seed", ChangedAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
		out[tn.ID] = id
	}
	return out
}

// Tenant A's policy ids answer exactly like missing ones in tenant B.
func TestAbacAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	ids := seedAbac(t, f)
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	before := storetest.Dump(t, f.DB, f.A.ID)
	const missingID = "00000000-0000-4000-8000-00000000dead"
	for _, c := range []struct{ method, suffix, body string }{
		{"GET", "", ""},
		{"PUT", "", `{"version":1,"name":"x","condition":` + engCond + `}`},
		{"POST", "/retire", `{"reason":"x"}`},
	} {
		cross := reqDo(h, admin, c.method, "/api/abac/policies/"+ids[f.A.ID]+c.suffix, c.body)
		missing := reqDo(h, admin, c.method, "/api/abac/policies/"+missingID+c.suffix, c.body)
		if cross.Code != 404 || cross.Body.String() != missing.Body.String() || leaks(cross.Body.String()) {
			t.Errorf("policy %s %s: %d %s (missing: %s)", c.method, c.suffix, cross.Code, cross.Body, missing.Body)
		}
	}
	cross := reqDo(h, admin, "POST", "/api/abac/simulate", `{"policy_id":"`+ids[f.A.ID]+`","condition":`+engCond+`}`)
	missing := reqDo(h, admin, "POST", "/api/abac/simulate", `{"policy_id":"`+missingID+`","condition":`+engCond+`}`)
	if cross.Code != 404 || cross.Body.String() != missing.Body.String() {
		t.Errorf("simulate against A's policy: %d %s", cross.Code, cross.Body)
	}
	// a role rule or a catalog binding naming A's policy is refused as a missing one
	rec := reqDo(h, admin, "POST", "/api/roles", fmt.Sprintf(`{"name":"x","risk":"low","birthright":{"policy":"%s"},"entitlement_group_ids":[%d]}`,
		ids[f.A.ID], f.B.IDs["group:okta:eng"]))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "attribute policy not found") {
		t.Errorf("A's policy in a rule: %d %s", rec.Code, rec.Body)
	}
	gid := f.B.IDs["group:okta:platform"]
	if rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", gid), `{"requestable":true,"risk":"low"}`); rec.Code != 200 {
		t.Fatalf("catalog put: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d/policy", gid), `{"policy_id":"`+ids[f.A.ID]+`"}`)
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "policy_not_found") {
		t.Errorf("binding A's policy: %d %s", rec.Code, rec.Body)
	}
	for _, path := range []string{"/api/abac/policies", "/api/abac/bindings"} {
		if rec := reqDo(h, admin, "GET", path, ""); leaks(rec.Body.String()) || strings.Contains(rec.Body.String(), ids[f.A.ID]) {
			t.Errorf("%s lists tenant A's data", path)
		}
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("B's policy calls changed tenant A")
	}
}
