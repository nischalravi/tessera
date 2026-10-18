package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// seedRoles adds one role per tenant (with bob as a manual member and a
// pending role request for alice); tenant A's description carries the
// sentinel. It returns the role and request ids by tenant.
func seedRoles(t *testing.T, f *storetest.Fixture) (map[tenancy.ID]string, map[tenancy.ID]string) {
	t.Helper()
	rolesBy, reqsBy := map[tenancy.ID]string{}, map[tenancy.ID]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		desc := "platform access"
		if tn.ID == f.A.ID {
			desc += " " + storetest.Sentinel
		}
		id, req := "role-"+tn.Slug, "rreq-"+tn.Slug
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			u := &store.PlatformUser{DisplayName: "Role admin", CreatedAt: storetest.Now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			if err := c.InsertBusinessRole(&store.BusinessRole{ID: id, Name: "Platform " + tn.Slug, Description: desc,
				Risk: "low", Requestable: true, Status: store.RoleActive, Version: 1, CreatedAt: storetest.Now,
				UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			if err := c.SetRoleEntitlements(id, []int64{tn.IDs["group:okta:platform"]}); err != nil {
				return err
			}
			if err := c.AddRoleVersion(&store.RoleVersion{RoleID: id, Version: 1, Snapshot: `{"description":"` + desc + `"}`,
				Actor: "seed", ChangedAt: storetest.Now}); err != nil {
				return err
			}
			if err := c.AddRoleMember(&store.RoleMember{RoleID: id, IdentityID: tn.IDs["bob"], Source: store.MemberManual,
				AssignedAt: storetest.Now}); err != nil {
				return err
			}
			return c.InsertRoleRequest(&store.RoleRequest{ID: req, RoleID: id, BeneficiaryID: tn.IDs["alice"],
				RequestedBy: u.ID.String(), Justification: desc, RequestedAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
		rolesBy[tn.ID], reqsBy[tn.ID] = id, req
	}
	return rolesBy, reqsBy
}

func TestRolesAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	b := f.B.IDs
	body := fmt.Sprintf(`{"name":"Engineer","description":"Day one","risk":"medium","requestable":true,
		"birthright":{"department":["Engineering"]},"entitlement_group_ids":[%d,%d],"note":"v1"}`,
		b["group:okta:eng"], b["group:okta:platform"])

	// a viewer cannot create; a dry run shows the plan and saves nothing
	if rec := reqDo(h, alice, "POST", "/api/roles", body); rec.Code != 403 {
		t.Errorf("viewer create: %d", rec.Code)
	}
	rec := reqDo(h, admin, "POST", "/api/roles?dry_run=1", body)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"dry_run":true`) || !strings.Contains(rec.Body.String(), `"members_added":2`) {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "GET", "/api/roles", ""); strings.Contains(rec.Body.String(), "Engineer") {
		t.Fatalf("dry run saved: %s", rec.Body)
	}
	rec = reqDo(h, admin, "POST", "/api/roles", body)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var cv changeView
	_ = json.Unmarshal(rec.Body.Bytes(), &cv)
	id := cv.Role.ID
	if cv.Role.MemberCount != 2 || cv.Plan.Adds != 1 || len(cv.Role.Members) != 2 {
		t.Fatalf("created: %s", rec.Body)
	}
	// update with a stale version, then the right one (drop platform)
	upd := fmt.Sprintf(`{"version":%%d,"name":"Engineer","risk":"medium","requestable":true,
		"birthright":{"department":["Engineering"]},"entitlement_group_ids":[%d]}`, b["group:okta:eng"])
	if rec := reqDo(h, admin, "PUT", "/api/roles/"+id, fmt.Sprintf(upd, 5)); rec.Code != 409 {
		t.Errorf("stale update: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "PUT", "/api/roles/"+id, fmt.Sprintf(upd, 1))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"grants_removed":1`) || !strings.Contains(rec.Body.String(), `"version":2`) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "GET", "/api/roles/"+id+"/versions", "")
	if !strings.Contains(rec.Body.String(), `"version":2`) || !strings.Contains(rec.Body.String(), `"note":"v1"`) {
		t.Errorf("versions: %s", rec.Body)
	}
	// alice (a rule member) holds it; bob requests nothing; drift is clean
	rec = reqDo(h, alice, "GET", "/api/roles", "")
	if !strings.Contains(rec.Body.String(), `"held":true`) || !strings.Contains(rec.Body.String(), `"can_manage":false`) {
		t.Errorf("alice list: %s", rec.Body)
	}
	if rec := reqDo(h, admin, "GET", "/api/roles/"+id+"/drift", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"missing":[]`) {
		t.Errorf("drift: %d %s", rec.Code, rec.Body)
	}
	// rule members cannot be removed by hand; bob is assigned and removed
	if rec := reqDo(h, admin, "POST", fmt.Sprintf("/api/roles/%s/members/%d/remove", id, b["alice"]), `{"reason":"x"}`); rec.Code != 409 {
		t.Errorf("remove rule member: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/roles/"+id+"/members", fmt.Sprintf(`{"identity_id":%d}`, b["bob"])); rec.Code != 200 {
		t.Fatalf("assign: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", fmt.Sprintf("/api/roles/%s/members/%d/remove", id, b["bob"]), `{"reason":"moved teams"}`); rec.Code != 200 {
		t.Fatalf("unassign: %d %s", rec.Code, rec.Body)
	}
	// a requestable role: carol is a member already, bob requests it through alice? no: alice requests for herself
	// (she holds it), so the admin creates a second role to request
	rec = reqDo(h, admin, "POST", "/api/roles", fmt.Sprintf(`{"name":"Payments","risk":"high","requestable":true,"entitlement_group_ids":[%d]}`,
		b["group:okta:payments-clerks"]))
	_ = json.Unmarshal(rec.Body.Bytes(), &cv)
	pay := cv.Role.ID
	rec = reqDo(h, alice, "POST", "/api/role-requests", fmt.Sprintf(`{"role_id":"%s","justification":"month-end"}`, pay))
	if rec.Code != 201 {
		t.Fatalf("request: %d %s", rec.Code, rec.Body)
	}
	var q roleRequestView
	_ = json.Unmarshal(rec.Body.Bytes(), &q)
	if !q.CanCancel || q.CanApprove {
		t.Errorf("request view: %s", rec.Body)
	}
	if rec := reqDo(h, alice, "POST", "/api/role-requests/"+q.ID+"/approve", `{}`); rec.Code != 403 {
		t.Errorf("viewer approves: %d", rec.Code)
	}
	rec = reqDo(h, admin, "GET", "/api/role-requests?scope=pending", "")
	if !strings.Contains(rec.Body.String(), q.ID) || !strings.Contains(rec.Body.String(), `"can_approve":true`) {
		t.Errorf("pending: %s", rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/role-requests/"+q.ID+"/approve", `{"reason":"ok"}`); rec.Code != 200 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	// retire with a dry run first
	rec = reqDo(h, admin, "POST", "/api/roles/"+pay+"/retire?dry_run=1", `{"reason":"moved to ERP"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"grants_removed":1`) {
		t.Errorf("retire dry run: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/roles/"+pay+"/retire", `{"reason":"moved to ERP"}`); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"status":"retired"`) {
		t.Errorf("retire: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/roles/"+pay+"/reconcile", ""); rec.Code != 409 {
		t.Errorf("reconcile retired: %d %s", rec.Code, rec.Body)
	}
	acts := reqAuditActions(t, f, f.B.ID)
	for a, n := range map[string]int{"role.create": 2, "role.update": 1, "role.assign": 2, "role.unassign": 1,
		"role.request.submit": 1, "role.request.approve": 1, "role.retire": 1} {
		if acts[a] != n {
			t.Errorf("audit %s = %d, want %d", a, acts[a], n)
		}
	}
}

func TestRolesAPI_StepUpAndRBAC(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	roleIDs, _ := seedRoles(t, f)
	id := roleIDs[f.B.ID]
	for _, c := range []struct {
		role       auth.Role
		list, read int
		manage     int
	}{
		{auth.RoleViewer, 200, 200, 403},
		{auth.RoleOperator, 200, 200, 403},
		{auth.RoleAuditor, 200, 200, 403},
		{auth.RoleTenantAdmin, 200, 200, 403},
		{auth.RolePolicyAdmin, 200, 200, 200},
		{auth.RoleBreakGlass, 403, 403, 403},
	} {
		l := reqLogin(t, f, string(c.role)+"@b.example", []auth.Role{c.role}, "")
		if rec := reqDo(h, l, "GET", "/api/roles", ""); rec.Code != c.list {
			t.Errorf("%s list: %d", c.role, rec.Code)
		}
		if rec := reqDo(h, l, "GET", "/api/roles/"+id, ""); rec.Code != c.read {
			t.Errorf("%s read: %d", c.role, rec.Code)
		}
		if rec := reqDo(h, l, "POST", "/api/roles/"+id+"/reconcile?dry_run=1", ""); rec.Code != c.manage {
			t.Errorf("%s reconcile: %d %s", c.role, rec.Code, rec.Body)
		}
	}
	// a 20-minute-old sign-in must sign in again before changing a role
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	for _, path := range []string{"/api/roles/" + id + "/reconcile", "/api/roles/" + id + "/retire", "/api/roles"} {
		if rec := serve(h, authed(stale, "POST", path, `{"reason":"x"}`)); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("POST %s with a stale sign-in: %d %s", path, rec.Code, rec.Body)
		}
	}
}

// Tenant A's role and request ids answer exactly like missing ones in tenant B.
func TestRolesAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	roleIDs, reqIDs := seedRoles(t, f)
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	before := storetest.Dump(t, f.DB, f.A.ID)
	bob := f.B.IDs["bob"]
	for _, c := range []struct{ method, suffix, body string }{
		{"GET", "", ""}, {"GET", "/versions", ""}, {"GET", "/drift", ""},
		{"PUT", "", fmt.Sprintf(`{"version":1,"name":"x","risk":"low","entitlement_group_ids":[%d]}`, f.B.IDs["group:okta:eng"])},
		{"POST", "/retire", `{"reason":"x"}`}, {"POST", "/reconcile", ""},
		{"POST", "/members", fmt.Sprintf(`{"identity_id":%d}`, bob)},
		{"POST", fmt.Sprintf("/members/%d/remove", bob), `{"reason":"x"}`},
	} {
		cross := reqDo(h, admin, c.method, "/api/roles/"+roleIDs[f.A.ID]+c.suffix, c.body)
		missing := reqDo(h, admin, c.method, "/api/roles/00000000-0000-4000-8000-00000000dead"+c.suffix, c.body)
		if cross.Code != 404 || cross.Body.String() != missing.Body.String() || leaks(cross.Body.String()) {
			t.Errorf("role %s %s: %d %s (missing: %s)", c.method, c.suffix, cross.Code, cross.Body, missing.Body)
		}
	}
	for _, c := range []struct{ suffix, body string }{{"/approve", `{}`}, {"/deny", `{"reason":"x"}`}, {"/cancel", ""}} {
		cross := reqDo(h, admin, "POST", "/api/role-requests/"+reqIDs[f.A.ID]+c.suffix, c.body)
		missing := reqDo(h, admin, "POST", "/api/role-requests/00000000-0000-4000-8000-00000000dead"+c.suffix, c.body)
		if cross.Code != 404 || cross.Body.String() != missing.Body.String() || leaks(cross.Body.String()) {
			t.Errorf("request %s: %d %s (missing: %s)", c.suffix, cross.Code, cross.Body, missing.Body)
		}
	}
	for _, path := range []string{"/api/roles", "/api/role-requests?scope=all", "/api/role-requests?scope=pending"} {
		if rec := reqDo(h, admin, "GET", path, ""); leaks(rec.Body.String()) || strings.Contains(rec.Body.String(), roleIDs[f.A.ID]) {
			t.Errorf("%s lists tenant A's data", path)
		}
	}
	// B naming A's group, owner or role: as for missing ones
	rec := reqDo(h, admin, "POST", "/api/roles", fmt.Sprintf(`{"name":"x","risk":"low","entitlement_group_ids":[%d]}`,
		f.A.IDs["group:okta:eng"]))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "group_not_found") {
		t.Errorf("A's group: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "POST", "/api/roles", fmt.Sprintf(`{"name":"x","risk":"low","owner_identity_id":%d,"entitlement_group_ids":[%d]}`,
		f.A.IDs["alice"], f.B.IDs["group:okta:eng"]))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "owner_not_found") {
		t.Errorf("A's owner: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "POST", "/api/role-requests", fmt.Sprintf(`{"role_id":"%s","beneficiary_id":%d,"justification":"x"}`,
		roleIDs[f.A.ID], bob))
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "role_not_found") {
		t.Errorf("A's role request: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("B's role calls changed tenant A")
	}
}
