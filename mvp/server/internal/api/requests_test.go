package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// seedRequestLines files one pending request line in each fixture tenant
// (bob asks for okta:platform; tenant A's justification carries the
// sentinel) and returns each tenant's line id.
func seedRequestLines(t *testing.T, f *storetest.Fixture) map[tenancy.ID]string {
	t.Helper()
	out := map[tenancy.ID]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		just := "needs the platform group"
		if tn.ID == f.A.ID {
			just += " " + storetest.Sentinel
		}
		line, item := "line-"+tn.Slug, "item-"+tn.Slug
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			u := &store.PlatformUser{DisplayName: "Requester", CreatedAt: storetest.Now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			if err := c.PutCatalogItem(&store.CatalogItem{ID: item, GroupID: tn.IDs["group:okta:platform"], Requestable: true,
				Risk: "low", UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			return c.InsertRequestLine(&store.RequestLine{ID: line, BatchID: "batch-" + tn.Slug, CatalogItemID: item,
				GroupID: tn.IDs["group:okta:platform"], BeneficiaryID: tn.IDs["bob"], AccountID: tn.IDs["acct:okta:bob"],
				RequestedBy: u.ID.String(), Justification: just, RequestedAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
		out[tn.ID] = line
	}
	return out
}

// reqLogin signs a user with roles into tenant B, optionally as a person.
func reqLogin(t *testing.T, f *storetest.Fixture, email string, roles []auth.Role, person string) authtest.Login {
	t.Helper()
	u := authtest.User{Email: email, Roles: roles}
	if person != "" {
		id := f.B.IDs[person]
		u.IdentityID = &id
	}
	return signIn(t, f.DB, f.B.ID, u, authtest.Phr, storetest.Now)
}

func TestRequestsAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")

	// the policy admin puts okta:platform in the catalog
	rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", f.B.IDs["group:okta:platform"]),
		`{"requestable":true,"risk":"medium","description":"Platform team"}`)
	if rec.Code != 200 {
		t.Fatalf("put item: %d %s", rec.Code, rec.Body)
	}
	var item catalogEntry
	_ = json.Unmarshal(rec.Body.Bytes(), &item)
	if item.ID == nil || item.Risk != "medium" {
		t.Fatalf("item %s", rec.Body)
	}
	// alice sees it and requests it for herself, but not for bob
	rec = reqDo(h, alice, "GET", "/api/catalog", "")
	if !strings.Contains(rec.Body.String(), "Platform team") ||
		!strings.Contains(rec.Body.String(), fmt.Sprintf(`"me":{"id":%d`, f.B.IDs["alice"])) ||
		!strings.Contains(rec.Body.String(), `"can_request_for_others":false`) {
		t.Errorf("catalog: %s", rec.Body)
	}
	if rec := reqDo(h, alice, "GET", "/api/catalog?all=1", ""); rec.Code != 403 {
		t.Errorf("viewer full catalog: %d", rec.Code)
	}
	rec = reqDo(h, alice, "POST", "/api/requests",
		fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":["%s"],"justification":"x"}`, f.B.IDs["bob"], *item.ID))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "for_others_not_allowed") {
		t.Errorf("for bob: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, alice, "POST", "/api/requests",
		fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":["%s"],"justification":"joining the platform team"}`, f.B.IDs["alice"], *item.ID))
	if rec.Code != 201 {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	var sub struct {
		Lines []lineView `json:"lines"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)
	if len(sub.Lines) != 1 || !sub.Lines[0].CanCancel || sub.Lines[0].CanApprove {
		t.Fatalf("lines %s", rec.Body)
	}
	id := sub.Lines[0].ID
	// she cannot approve it; the admin sees it as pending and approves
	if rec := reqDo(h, alice, "POST", "/api/requests/"+id+"/approve", `{}`); rec.Code != 403 {
		t.Errorf("viewer approves: %d", rec.Code)
	}
	rec = reqDo(h, admin, "GET", "/api/requests?scope=pending", "")
	if !strings.Contains(rec.Body.String(), id) || !strings.Contains(rec.Body.String(), `"can_approve":true`) {
		t.Errorf("pending: %s", rec.Body)
	}
	rec = reqDo(h, admin, "POST", "/api/requests/"+id+"/approve", `{"reason":"team lead asked"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"approved"`) {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	// alice's history shows it; she removes her own access
	rec = reqDo(h, alice, "GET", "/api/requests/"+id, "")
	if !strings.Contains(rec.Body.String(), `"event":"approved"`) || !strings.Contains(rec.Body.String(), `"can_remove":true`) {
		t.Errorf("detail: %s", rec.Body)
	}
	if rec := reqDo(h, alice, "POST", "/api/requests/"+id+"/remove", ""); rec.Code != 200 {
		t.Errorf("remove: %d %s", rec.Code, rec.Body)
	}
	acts := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"catalog.item.put", "request.submit", "request.approve", "request.remove"} {
		if acts[a] != 1 {
			t.Errorf("audit %s = %d", a, acts[a])
		}
	}
}

func TestRequestsAPI_Visibility(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	lines := seedRequestLines(t, f)
	// carol (no role beyond requesting, linked to carol) cannot see bob's line
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleTenantAdmin}, "carol")
	rec := reqDo(h, carol, "GET", "/api/requests/"+lines[f.B.ID], "")
	if rec.Code != 200 { // tenant admins hold graph.read
		t.Errorf("tenant admin detail: %d", rec.Code)
	}
	if rec := reqDo(h, carol, "POST", "/api/requests/"+lines[f.B.ID]+"/cancel", ""); rec.Code != 404 {
		t.Errorf("cancel someone else's: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, carol, "GET", "/api/requests?scope=bogus", ""); rec.Code != 422 {
		t.Errorf("bad scope: %d", rec.Code)
	}
}

// Tenant A's request ids answer exactly like missing ones in tenant B.
func TestRequestsAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	lines := seedRequestLines(t, f)
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	before := storetest.Dump(t, f.DB, f.A.ID)
	for _, c := range []struct{ method, suffix, body string }{
		{"GET", "", ""}, {"POST", "/approve", `{}`}, {"POST", "/deny", `{"reason":"x"}`},
		{"POST", "/cancel", ""}, {"POST", "/remove", `{"reason":"x"}`},
	} {
		cross := reqDo(h, admin, c.method, "/api/requests/"+lines[f.A.ID]+c.suffix, c.body)
		missing := reqDo(h, admin, c.method, "/api/requests/00000000-0000-4000-8000-00000000dead"+c.suffix, c.body)
		if cross.Code != 404 || cross.Body.String() != missing.Body.String() || leaks(cross.Body.String()) {
			t.Errorf("%s %s: %d %s (missing: %s)", c.method, c.suffix, cross.Code, cross.Body, missing.Body)
		}
	}
	for _, scope := range []string{"all", "pending", "mine"} {
		if rec := reqDo(h, admin, "GET", "/api/requests?scope="+scope, ""); leaks(rec.Body.String()) || strings.Contains(rec.Body.String(), lines[f.A.ID]) {
			t.Errorf("scope=%s lists tenant A's line", scope)
		}
	}
	// B submitting A's catalog item or beneficiary: as for missing ones
	rec := reqDo(h, admin, "POST", "/api/requests", fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":["item-%s"],"justification":"x"}`,
		f.B.IDs["bob"], f.A.Slug))
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "item_not_found") {
		t.Errorf("A's item: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("B's requests changed tenant A")
	}
}

func reqDo(h http.Handler, l authtest.Login, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	l.Apply(req)
	return serve(h, req)
}

func reqAuditActions(t *testing.T, f *storetest.Fixture, tenant tenancy.ID) map[string]int {
	t.Helper()
	out := map[string]int{}
	if err := f.DB.ReadTenant(context.Background(), tenant, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			out[e.Action]++
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
