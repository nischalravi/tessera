package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Approval routing over the API (issue #165): okta:platform routes manager
// → decider. alice (a viewer) asks; carol, her manager (a viewer too),
// approves the first stage from her inbox; the policy admin the second.
func TestApprovalsAPI_RoutedFlow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol")
	zed := reqLogin(t, f, "zed@b.example", []auth.Role{auth.RoleViewer}, "")

	rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", f.B.IDs["group:okta:platform"]),
		`{"requestable":true,"risk":"medium","approval_stages":["manager","decider"],"escalate_after_hours":24}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"approval":{"stages":["manager","decider"],"escalate_after_hours":24}`) {
		t.Fatalf("put item: %d %s", rec.Code, rec.Body)
	}
	var item catalogEntry
	_ = json.Unmarshal(rec.Body.Bytes(), &item)
	rec = reqDo(h, alice, "POST", "/api/requests",
		fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":["%s"],"justification":"platform rotation"}`, f.B.IDs["alice"], *item.ID))
	if rec.Code != 201 {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	var sub struct {
		Lines []lineView `json:"lines"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)
	id := sub.Lines[0].ID
	if st := sub.Lines[0].Stages; len(st) != 2 || st[0].Kind != "manager" || st[0].Status != "waiting" || st[0].Assignee == nil {
		t.Fatalf("stages %+v", st)
	}

	// carol delegates to zed for a week, then revokes; meanwhile zed sees the item
	rec = reqDo(h, carol, "POST", "/api/approvals/delegations", fmt.Sprintf(`{"to_user_id":"%s","starts_at":"%s","ends_at":"%s","reason":"on leave"}`,
		zed.UserID, storetest.Now.Add(-time.Minute).Format(time.RFC3339), storetest.Now.Add(7*24*time.Hour).Format(time.RFC3339)))
	if rec.Code != 201 {
		t.Fatalf("delegate: %d %s", rec.Code, rec.Body)
	}
	var d delegationView
	_ = json.Unmarshal(rec.Body.Bytes(), &d)
	if rec := reqDo(h, zed, "GET", "/api/approvals/inbox", ""); !strings.Contains(rec.Body.String(), id) || !strings.Contains(rec.Body.String(), `"on_behalf_of":{`) {
		t.Errorf("zed's inbox: %s", rec.Body)
	}
	if rec := reqDo(h, carol, "POST", "/api/approvals/delegations/"+d.ID+"/revoke", ""); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, zed, "GET", "/api/approvals/inbox", ""); strings.Contains(rec.Body.String(), id) {
		t.Errorf("revoked delegate still sees it: %s", rec.Body)
	}

	// the decider cannot act before the manager (and before escalation)
	if rec := reqDo(h, admin, "POST", "/api/requests/"+id+"/approve", `{}`); rec.Code != 403 || !strings.Contains(rec.Body.String(), "not_an_approver") {
		t.Errorf("decider first: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, carol, "GET", "/api/approvals/inbox", "")
	if !strings.Contains(rec.Body.String(), id) || !strings.Contains(rec.Body.String(), `"kind":"manager"`) {
		t.Fatalf("carol's inbox: %s", rec.Body)
	}
	rec = reqDo(h, carol, "POST", "/api/requests/"+id+"/approve", `{"reason":"on my team"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"pending"`) {
		t.Fatalf("manager approves: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "POST", "/api/requests/"+id+"/approve", `{}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"approved"`) {
		t.Fatalf("decider approves: %d %s", rec.Code, rec.Body)
	}
	acts := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"approval.policy.put", "approval.delegate", "approval.delegation.revoke", "request.stage.approve", "request.approve"} {
		if acts[a] != 1 {
			t.Errorf("audit %s = %d (%v)", a, acts[a], acts)
		}
	}
}

// Tenant B cannot see or revoke tenant A's delegations.
func TestApprovalsAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	viewer := func(email string) authtest.User { return authtest.User{Email: email, Roles: []auth.Role{auth.RoleViewer}} }
	ua := signIn(t, f.DB, f.A.ID, viewer("a1@a.example"), authtest.Phr, storetest.Now)
	ua2 := signIn(t, f.DB, f.A.ID, viewer("a2@a.example"), authtest.Phr, storetest.Now)
	rec := reqDo(h, ua, "POST", "/api/approvals/delegations", fmt.Sprintf(`{"to_user_id":"%s","starts_at":"%s","ends_at":"%s","reason":"leave"}`,
		ua2.UserID, storetest.Now.Format(time.RFC3339), storetest.Now.Add(time.Hour).Format(time.RFC3339)))
	if rec.Code != 201 {
		t.Fatalf("A delegates: %d %s", rec.Code, rec.Body)
	}
	var d delegationView
	_ = json.Unmarshal(rec.Body.Bytes(), &d)
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	cross := reqDo(h, admin, "POST", "/api/approvals/delegations/"+d.ID+"/revoke", "")
	missing := reqDo(h, admin, "POST", "/api/approvals/delegations/00000000-0000-4000-8000-00000000dead/revoke", "")
	if cross.Code != 404 || cross.Body.String() != missing.Body.String() {
		t.Errorf("revoke A's: %d %s (missing %s)", cross.Code, cross.Body, missing.Body)
	}
	if rec := reqDo(h, admin, "GET", "/api/approvals/delegations?all=1", ""); strings.Contains(rec.Body.String(), d.ID) {
		t.Error("B lists A's delegation")
	}
	// B cannot delegate to A's user
	rec = reqDo(h, admin, "POST", "/api/approvals/delegations", fmt.Sprintf(`{"to_user_id":"%s","starts_at":"%s","ends_at":"%s","reason":"x"}`,
		ua2.UserID, storetest.Now.Format(time.RFC3339), storetest.Now.Add(time.Hour).Format(time.RFC3339)))
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "user_not_found") {
		t.Errorf("delegate to A's user: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "GET", "/api/approvals/delegates", ""); strings.Contains(rec.Body.String(), ua2.UserID.String()) {
		t.Error("B's delegate list has A's user")
	}
}
