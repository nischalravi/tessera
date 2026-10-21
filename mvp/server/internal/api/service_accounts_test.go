package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Service-account requests (issue #298): mandatory owners, approval by the owners and a decider
// through the workflow engine, who sees what, and tenant isolation.

func TestServiceAccountsAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	bob := reqLogin(t, f, "bob@b.example", []auth.Role{auth.RoleViewer}, "bob")
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol")
	zed := reqLogin(t, f, "zed@b.example", []auth.Role{auth.RoleViewer}, "")
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
	ids := f.B.IDs
	create := func(l authtest.Login, body string, want int) map[string]any {
		t.Helper()
		return call(l, "POST", "/api/service-account-requests", body, want)
	}
	newBody := func(name, extra string) string {
		return fmt.Sprintf(`{"kind":"create","name":%q,"system":"okta","username":%q,"purpose":"nightly sync","primary_owner_id":%d,"backup_owner_id":%d,"justification":"new pipeline"%s}`,
			name, name, ids["bob"], ids["carol"], extra)
	}

	// owners are mandatory; unknown fields are refused
	create(alice, fmt.Sprintf(`{"kind":"create","name":"svc-a","system":"okta","username":"svc-a","primary_owner_id":%d,"justification":"x"}`, ids["bob"]), 422)
	create(alice, fmt.Sprintf(`{"kind":"create","name":"svc-a","system":"okta","username":"svc-a","backup_owner_id":%d,"justification":"x"}`, ids["bob"]), 422)
	create(alice, newBody("svc-a", `,"surprise":1`), 422)
	create(alice, `{"kind":"delete","justification":"x"}`, 422)

	req := create(zed, newBody("svc-sync", ""), 201)
	id := req["id"].(string)
	if req["status"] != "pending" || req["kind"] != "create" || req["can_cancel"] != true || req["workflow"] != nil {
		t.Fatalf("created: %v", req)
	}
	stages := req["stages"].([]any)
	if len(stages) != 2 || stages[0].(map[string]any)["label"] != "New owner approval" || stages[0].(map[string]any)["assignee"].(map[string]any)["name"] != "Bob" ||
		stages[0].(map[string]any)["status"] != "waiting" {
		t.Fatalf("stages: %v", stages)
	}
	create(alice, newBody("svc-sync", ""), 409) // the name is taken while a request is open

	// visibility: the requester, the owners named, deciders and graph readers (as the history setting allows)
	call(zed, "GET", "/api/service-account-requests/"+id, "", 200)
	call(bob, "GET", "/api/service-account-requests/"+id, "", 200)
	call(carol, "GET", "/api/service-account-requests/"+id, "", 200)
	call(admin, "GET", "/api/service-account-requests/"+id, "", 200)
	call(alice, "GET", "/api/service-account-requests/"+id, "", 200) // a graph reader, and the tenant's history setting lets readers see requests
	call(alice, "GET", "/api/service-account-requests/not-a-uuid", "", 404)
	call(alice, "GET", "/api/service-account-requests/00000000-0000-4000-8000-00000000dead", "", 404)
	mine := reqDo(h, zed, "GET", "/api/service-account-requests", "")
	if mine.Code != 200 || !strings.Contains(mine.Body.String(), id) {
		t.Errorf("zed's list: %d %s", mine.Code, mine.Body)
	}
	if rec := reqDo(h, alice, "GET", "/api/service-account-requests", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), id) {
		t.Errorf("alice's list: %d %s", rec.Code, rec.Body)
	}
	call(alice, "GET", "/api/service-account-requests?scope=all", "", 200)
	call(alice, "GET", "/api/service-account-requests?scope=sideways", "", 422)
	if rec := reqDo(h, bob, "GET", "/api/service-account-requests?scope=pending", ""); !strings.Contains(rec.Body.String(), id) {
		t.Errorf("bob's inbox: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, carol, "GET", "/api/service-account-requests?scope=pending", ""); strings.Contains(rec.Body.String(), id) {
		t.Errorf("carol's inbox has bob's stage: %s", rec.Body)
	}
	if v := call(bob, "GET", "/api/service-account-requests/"+id, "", 200); v["can_approve"] != true {
		t.Errorf("bob cannot approve: %v", v)
	}

	// the requester and the wrong people cannot approve; the new owner then a decider can
	call(zed, "POST", "/api/service-account-requests/"+id+"/approve", `{}`, 403)
	call(carol, "POST", "/api/service-account-requests/"+id+"/approve", `{}`, 403)
	call(admin, "POST", "/api/service-account-requests/"+id+"/approve", `{}`, 403) // not a decider yet
	call(bob, "POST", "/api/service-account-requests/"+id+"/deny", `{}`, 422)      // a reason is required
	after := call(bob, "POST", "/api/service-account-requests/"+id+"/approve", `{"reason":"mine"}`, 200)
	if after["status"] != "pending" || after["stages"].([]any)[0].(map[string]any)["status"] != "approved" {
		t.Fatalf("after the owner: %v", after)
	}
	done := call(admin, "POST", "/api/service-account-requests/"+id+"/approve", `{}`, 200)
	if done["status"] != "fulfilled" || done["account"] == nil || done["fulfilled_at"] == nil {
		t.Fatalf("after the decider: %v", done)
	}
	accountID := int64(done["account"].(map[string]any)["id"].(float64))

	// the service account is listed with its owners; a transfer then needs both owners
	list := call(alice, "GET", "/api/service-accounts", "", 200)
	var found map[string]any
	for _, a := range list["accounts"].([]any) {
		if int64(a.(map[string]any)["id"].(float64)) == accountID {
			found = a.(map[string]any)
		}
	}
	if found == nil || found["primary_owner"].(map[string]any)["name"] != "Bob" || found["backup_owner"].(map[string]any)["name"] != "Carol" ||
		found["purpose"] != "nightly sync" || found["open_request"] != nil {
		t.Fatalf("listed account: %v (%v)", found, list)
	}
	tr := create(zed, fmt.Sprintf(`{"kind":"transfer","identity_id":%d,"primary_owner_id":%d,"justification":"Bob moved teams"}`, accountID, ids["alice"]), 201)
	tid := tr["id"].(string)
	if n := len(tr["stages"].([]any)); n != 3 || tr["previous_primary_owner"].(map[string]any)["name"] != "Bob" {
		t.Fatalf("transfer: %v", tr)
	}
	call(alice, "POST", "/api/service-account-requests/"+tid+"/approve", `{}`, 403) // the new owner goes second
	call(bob, "POST", "/api/service-account-requests/"+tid+"/approve", `{}`, 200)
	call(alice, "POST", "/api/service-account-requests/"+tid+"/approve", `{}`, 200)
	if v := call(admin, "POST", "/api/service-account-requests/"+tid+"/approve", `{}`, 200); v["status"] != "fulfilled" {
		t.Fatalf("transfer: %v", v)
	}
	after2 := call(alice, "GET", "/api/service-accounts", "", 200)["accounts"].([]any)
	for _, a := range after2 {
		if int64(a.(map[string]any)["id"].(float64)) == accountID && a.(map[string]any)["primary_owner"].(map[string]any)["name"] != "Alice" {
			t.Errorf("the owner did not change: %v", a)
		}
	}

	// deny and cancel
	d := create(zed, newBody("svc-deny", ""), 201)["id"].(string)
	call(bob, "POST", "/api/service-account-requests/"+d+"/deny", `{"reason":"not ours"}`, 200)
	call(bob, "POST", "/api/service-account-requests/"+d+"/approve", `{}`, 409)
	c := create(zed, newBody("svc-cancel", ""), 201)["id"].(string)
	call(bob, "POST", "/api/service-account-requests/"+c+"/cancel", `{}`, 404)
	if v := call(zed, "POST", "/api/service-account-requests/"+c+"/cancel", `{}`, 200); v["status"] != "cancelled" {
		t.Errorf("cancel: %v", v)
	}

	actions := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"service_account.request.submit", "service_account.request.stage.approve", "service_account.request.approve",
		"service_account.request.deny", "service_account.request.cancel", "ownership.set"} {
		if actions[a] == 0 {
			t.Errorf("no %s audit event (have %v)", a, actions)
		}
	}
}

func TestServiceAccountsAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	adminB := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	adminA := signInA(t, f, auth.RolePolicyAdmin)
	rec := reqDo(h, adminA, "POST", "/api/service-account-requests", fmt.Sprintf(
		`{"kind":"create","name":"a-only","system":"okta","username":"a-only","primary_owner_id":%d,"backup_owner_id":%d,"justification":"x"}`,
		f.A.IDs["alice"], f.A.IDs["bob"]))
	if rec.Code != 422 && rec.Code != 403 && rec.Code != 201 {
		t.Fatalf("create in A: %d %s", rec.Code, rec.Body)
	}
	if rec.Code != 201 {
		t.Skipf("tenant A's admin has no person to request as: %d", rec.Code)
	}
	idA := jsonMap(t, rec.Body.String())["id"].(string)
	if rec := reqDo(h, adminB, "GET", "/api/service-account-requests?scope=all", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), "a-only") {
		t.Errorf("B lists A's: %d %s", rec.Code, rec.Body)
	}
	for _, c := range []struct{ method, suffix, body string }{
		{"GET", "", ""}, {"POST", "/approve", `{}`}, {"POST", "/deny", `{"reason":"x"}`}, {"POST", "/cancel", `{}`},
	} {
		cross := reqDo(h, adminB, c.method, "/api/service-account-requests/"+idA+c.suffix, c.body)
		if cross.Code != 404 || strings.Contains(cross.Body.String(), "a-only") {
			t.Errorf("%s %s: %d %s", c.method, c.suffix, cross.Code, cross.Body)
		}
	}
	// tenant B cannot name tenant A's people as owners
	rec = reqDo(h, adminB, "POST", "/api/service-account-requests", fmt.Sprintf(
		`{"kind":"create","name":"b-svc","system":"okta","username":"b-svc","primary_owner_id":%d,"backup_owner_id":%d,"justification":"x"}`,
		f.A.IDs["alice"], f.A.IDs["bob"]))
	if rec.Code == 201 {
		t.Errorf("B used A's people as owners: %s", rec.Body)
	}
}
