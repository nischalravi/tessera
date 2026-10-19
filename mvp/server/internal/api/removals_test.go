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
)

func grantEdge(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, acct, group string) int64 {
	t.Helper()
	var id int64
	err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		e, err := c.EdgeBetween(fmt.Sprintf("account:%d", tn.IDs[acct]), fmt.Sprintf("group:%d", tn.IDs[group]))
		if err == nil {
			id = e.ID
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func hasEdge(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, acct, group string) bool {
	t.Helper()
	var ok bool
	if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		_, err := c.EdgeBetween(fmt.Sprintf("account:%d", tn.IDs[acct]), fmt.Sprintf("group:%d", tn.IDs[group]))
		ok = err == nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestRemovalAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	bob := reqLogin(t, f, "bob@b.example", []auth.Role{auth.RoleViewer}, "bob")
	edge := grantEdge(t, f, f.B, "acct:okta:alice", "group:okta:eng")
	body := fmt.Sprintf(`{"edge_id":%d,"justification":"no longer on the team"}`, edge)

	// alice asks for removal of her own grant; bob cannot ask for hers
	if rec := reqDo(h, bob, "POST", "/api/removal-requests", body); rec.Code != 403 || !strings.Contains(rec.Body.String(), "for_others_not_allowed") {
		t.Errorf("bob asks: %d %s", rec.Code, rec.Body)
	}
	rec := reqDo(h, alice, "POST", "/api/removal-requests", body)
	var q removalView
	if err := json.Unmarshal(rec.Body.Bytes(), &q); err != nil || rec.Code != 201 || q.Status != "pending" || !q.CanCancel || q.CanApprove ||
		q.Group.Name == "" || q.Beneficiary.ID != f.B.IDs["alice"] {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, alice, "POST", "/api/removal-requests", body); rec.Code != 409 {
		t.Errorf("second request: %d %s", rec.Code, rec.Body)
	}

	// it shows in My requests, and in the approver's Inbox but not in a stranger's
	if rec := reqDo(h, alice, "GET", "/api/removal-requests", ""); !strings.Contains(rec.Body.String(), q.ID) {
		t.Errorf("mine: %s", rec.Body)
	}
	if rec := reqDo(h, admin, "GET", "/api/removal-requests?scope=approvals", ""); !strings.Contains(rec.Body.String(), q.ID) ||
		!strings.Contains(rec.Body.String(), `"can_approve":true`) {
		t.Errorf("approver inbox: %s", rec.Body)
	}
	if rec := reqDo(h, bob, "GET", "/api/removal-requests?scope=approvals", ""); strings.Contains(rec.Body.String(), q.ID) {
		t.Errorf("bob's inbox lists alice's request: %s", rec.Body)
	}
	if rec := reqDo(h, bob, "GET", "/api/removal-requests", ""); strings.Contains(rec.Body.String(), q.ID) {
		t.Errorf("bob's list shows alice's request: %s", rec.Body)
	}

	// she cannot approve her own; a viewer who is not her approver cannot either; the admin approves and the grant goes
	if rec := reqDo(h, alice, "POST", "/api/removal-requests/"+q.ID+"/approve", `{}`); rec.Code != 403 {
		t.Errorf("self approve: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, bob, "POST", "/api/removal-requests/"+q.ID+"/approve", `{}`); rec.Code != 403 {
		t.Errorf("stranger approve: %d %s", rec.Code, rec.Body)
	}
	if !hasEdge(t, f, f.B, "acct:okta:alice", "group:okta:eng") {
		t.Fatal("the grant went before approval")
	}
	rec = reqDo(h, admin, "POST", "/api/removal-requests/"+q.ID+"/approve", `{"reason":"confirmed with the team lead"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"approved"`) || !strings.Contains(rec.Body.String(), `"outcome":"revoked"`) {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if hasEdge(t, f, f.B, "acct:okta:alice", "group:okta:eng") {
		t.Error("the grant is still there after approval")
	}
	acts := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"removal.request.submit", "removal.request.approve"} {
		if acts[a] != 1 {
			t.Errorf("audit %s = %d", a, acts[a])
		}
	}
	if rec := reqDo(h, admin, "POST", "/api/removal-requests/"+q.ID+"/approve", `{}`); rec.Code != 409 {
		t.Errorf("approve twice: %d", rec.Code)
	}
}

func TestRemovalAPI_DenyCancelAndInput(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	edge := grantEdge(t, f, f.B, "acct:okta:alice", "group:okta:eng")

	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"no justification": {fmt.Sprintf(`{"edge_id":%d}`, edge), 422},
		"no edge":          {`{"justification":"x"}`, 422},
		"unknown grant":    {`{"edge_id":999999,"justification":"x"}`, 404},
		"unknown field":    {fmt.Sprintf(`{"edge_id":%d,"justification":"x","y":1}`, edge), 422},
	} {
		if rec := reqDo(h, alice, "POST", "/api/removal-requests", tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, tc.want)
		}
	}

	rec := reqDo(h, alice, "POST", "/api/removal-requests", fmt.Sprintf(`{"edge_id":%d,"justification":"x"}`, edge))
	var q removalView
	_ = json.Unmarshal(rec.Body.Bytes(), &q)
	if rec := reqDo(h, admin, "POST", "/api/removal-requests/"+q.ID+"/deny", `{}`); rec.Code != 422 {
		t.Errorf("deny without a reason: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/removal-requests/"+q.ID+"/deny", `{"reason":"still needed"}`); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"status":"denied"`) {
		t.Errorf("deny: %d %s", rec.Code, rec.Body)
	}
	if !hasEdge(t, f, f.B, "acct:okta:alice", "group:okta:eng") {
		t.Error("a denied request removed the grant")
	}
	// a new request can be cancelled by its requester only
	rec = reqDo(h, alice, "POST", "/api/removal-requests", fmt.Sprintf(`{"edge_id":%d,"justification":"again"}`, edge))
	_ = json.Unmarshal(rec.Body.Bytes(), &q)
	if rec := reqDo(h, admin, "POST", "/api/removal-requests/"+q.ID+"/cancel", ""); rec.Code != 404 {
		t.Errorf("cancel by another: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, alice, "POST", "/api/removal-requests/"+q.ID+"/cancel", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"cancelled"`) {
		t.Errorf("cancel: %d %s", rec.Code, rec.Body)
	}
}

func TestRemovalAPI_ManagerApproves(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol")
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		m := f.B.IDs["carol"]
		return c.SetIdentityManager(f.B.IDs["alice"], &m)
	}); err != nil {
		t.Fatal(err)
	}
	edge := grantEdge(t, f, f.B, "acct:okta:alice", "group:okta:eng")
	rec := reqDo(h, alice, "POST", "/api/removal-requests", fmt.Sprintf(`{"edge_id":%d,"justification":"no longer needed"}`, edge))
	var q removalView
	_ = json.Unmarshal(rec.Body.Bytes(), &q)
	if rec := reqDo(h, carol, "GET", "/api/removal-requests?scope=approvals", ""); !strings.Contains(rec.Body.String(), q.ID) {
		t.Errorf("the manager's inbox: %s", rec.Body)
	}
	if rec := reqDo(h, carol, "POST", "/api/removal-requests/"+q.ID+"/approve", `{}`); rec.Code != 200 {
		t.Errorf("manager approve: %d %s", rec.Code, rec.Body)
	}
}

func TestRemovalAPI_StepUpAndCrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	adminB := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	edgeB := grantEdge(t, f, f.B, "acct:okta:alice", "group:okta:eng")
	edgeA := grantEdge(t, f, f.A, "acct:okta:alice", "group:okta:eng")

	rec := reqDo(h, alice, "POST", "/api/removal-requests", fmt.Sprintf(`{"edge_id":%d,"justification":"x"}`, edgeB))
	var q removalView
	_ = json.Unmarshal(rec.Body.Bytes(), &q)
	if rec := reqDo(h, stale, "POST", "/api/removal-requests/"+q.ID+"/approve", `{}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale approve: %d %s", rec.Code, rec.Body)
	}
	// tenant A's edge and request look missing to tenant B, and B's request to A
	if edgeA == edgeB {
		t.Fatal("the fixture gave both tenants the same edge id")
	}
	if rec := reqDo(h, alice, "POST", "/api/removal-requests", fmt.Sprintf(`{"edge_id":%d,"justification":"x"}`, edgeA)); rec.Code != 404 {
		t.Errorf("B filed a removal against A's grant: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"approve", "deny", "cancel"} {
		cross := reqDo(h, adminA, "POST", "/api/removal-requests/"+q.ID+"/"+p, `{"reason":"x"}`)
		missing := reqDo(h, adminA, "POST", "/api/removal-requests/00000000-0000-4000-8000-00000000dead/"+p, `{"reason":"x"}`)
		if cross.Code != 404 || cross.Code != missing.Code || cross.Body.String() != missing.Body.String() {
			t.Errorf("%s across tenants: %d %s vs missing %d %s", p, cross.Code, cross.Body, missing.Code, missing.Body)
		}
	}
	for _, path := range []string{"/api/removal-requests?scope=all", "/api/removal-requests?scope=pending", "/api/removal-requests?scope=approvals"} {
		if rec := reqDo(h, adminA, "GET", path, ""); rec.Code != 200 || strings.Contains(rec.Body.String(), q.ID) {
			t.Errorf("A lists B's request on %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if !hasEdge(t, f, f.B, "acct:okta:alice", "group:okta:eng") || !hasEdge(t, f, f.A, "acct:okta:alice", "group:okta:eng") {
		t.Error("a refused request removed a grant")
	}
	if rec := reqDo(h, adminB, "GET", "/api/removal-requests?scope=bogus", ""); rec.Code != 422 {
		t.Errorf("bad scope: %d", rec.Code)
	}
}
