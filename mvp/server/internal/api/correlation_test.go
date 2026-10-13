package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func corrDo(h http.Handler, l authtest.Login, method, path, body string) *httptest.ResponseRecorder {
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

func policyAdmin(t *testing.T, f *storetest.Fixture, tenant tenancy.ID, email string) authtest.Login {
	t.Helper()
	return signIn(t, f.DB, tenant, authtest.User{Email: email, Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
}

func auditActions(t *testing.T, f *storetest.Fixture, tenant tenancy.ID) map[string]int {
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

func TestCorrelationAPI_LinkMergeUnmerge(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	ids := f.B.IDs
	l := policyAdmin(t, f, f.B.ID, "pa@b.example")

	// re-attribute dave's AWS account to carol
	rec := corrDo(h, l, "POST", fmt.Sprintf("/api/accounts/%d/link", ids["acct:aws:dave-iam"]),
		fmt.Sprintf(`{"identity_id":%d,"reason":"AWS team confirmed"}`, ids["carol"]))
	if rec.Code != 200 {
		t.Fatalf("link: %d %s", rec.Code, rec.Body)
	}
	var link struct {
		Account  accountView  `json:"account"`
		Decision decisionView `json:"decision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &link); err != nil || link.Account.IdentityID == nil ||
		*link.Account.IdentityID != ids["carol"] || link.Decision.DecidedBy == "" {
		t.Fatalf("link body %s (%v)", rec.Body, err)
	}
	rec = corrDo(h, l, "GET", "/api/correlation/decisions", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "AWS team confirmed") {
		t.Errorf("decisions: %d %s", rec.Code, rec.Body)
	}
	// refusals carry a stable code and change nothing
	rec = corrDo(h, l, "POST", fmt.Sprintf("/api/accounts/%d/link", ids["acct:okta:alice"]),
		fmt.Sprintf(`{"identity_id":%d,"reason":""}`, ids["bob"]))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"reason_required"`) {
		t.Errorf("no reason: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, l, "POST", fmt.Sprintf("/api/accounts/%d/link", ids["acct:okta:alice"]),
		fmt.Sprintf(`{"identity_id":%d,"reason":"x","extra":1}`, ids["bob"]))
	if rec.Code != 422 {
		t.Errorf("unknown field: %d %s", rec.Code, rec.Body)
	}

	// merge carol into alice, then undo it. Both are employees with access, so a
	// second reviewer must approve: the request alone changes nothing.
	l2 := policyAdmin(t, f, f.B.ID, "pa2@b.example")
	rec = corrDo(h, l, "POST", fmt.Sprintf("/api/identities/%d/merge", ids["carol"]),
		fmt.Sprintf(`{"into":%d,"reason":"duplicate HR record"}`, ids["alice"]))
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"pending_approval"`) {
		t.Fatalf("merge request: %d %s", rec.Code, rec.Body)
	}
	var pend struct {
		Request mergeRequestView `json:"request"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pend); err != nil || len(pend.Request.Risk) == 0 {
		t.Fatalf("request body %s (%v)", rec.Body, err)
	}
	if rec = corrDo(h, l, "GET", fmt.Sprintf("/api/identities/%d", ids["carol"]), ""); strings.Contains(rec.Body.String(), `"merged"`) {
		t.Error("a merge waiting for a second reviewer was applied")
	}
	rec = corrDo(h, l, "POST", "/api/identity-merge-requests/"+pend.Request.ID+"/approve", `{}`)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "second_reviewer_required") {
		t.Fatalf("self-approval: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, l2, "POST", "/api/identity-merge-requests/"+pend.Request.ID+"/approve", `{}`)
	if rec.Code != 200 {
		t.Fatalf("approval: %d %s", rec.Code, rec.Body)
	}
	var appr struct {
		Merge mergeView `json:"merge"`
	}
	m := &appr.Merge
	if err := json.Unmarshal(rec.Body.Bytes(), &appr); err != nil || m.SurvivorID != ids["alice"] || len(m.Moves) == 0 ||
		!m.UnmergeBefore.Equal(storetest.Now.Add(180*24*time.Hour)) {
		t.Fatalf("approval body %s (%v)", rec.Body, err)
	}
	rec = corrDo(h, l, "GET", fmt.Sprintf("/api/identities/%d", ids["carol"]), "")
	if !strings.Contains(rec.Body.String(), `"merged"`) {
		t.Errorf("merged identity detail: %.300s", rec.Body)
	}
	rec = corrDo(h, l, "GET", "/api/identity-merges", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), m.ID) {
		t.Errorf("merges: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, l, "POST", fmt.Sprintf("/api/identity-merges/%s/unmerge", m.ID), `{"reason":"wrong person"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"restored"`) {
		t.Fatalf("unmerge: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, l, "POST", fmt.Sprintf("/api/identity-merges/%s/unmerge", m.ID), `{"reason":"again"}`)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "already_unmerged") {
		t.Errorf("second unmerge: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, l, "DELETE", fmt.Sprintf("/api/accounts/%d/link", ids["acct:aws:dave-iam"]), "")
	if rec.Code != 200 {
		t.Errorf("release: %d %s", rec.Code, rec.Body)
	}

	acts := auditActions(t, f, f.B.ID)
	for _, a := range []string{"identity.account.link", "identity.merge.request", "identity.merge.approve", "identity.merge", "identity.unmerge", "identity.account.release"} {
		if acts[a] != 1 {
			t.Errorf("audit %s = %d, want 1 (%v)", a, acts[a], acts)
		}
	}
}

func TestCorrelationAPI_NeedsPermissionAndStepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	ids := f.B.IDs
	link := func(l authtest.Login) *httptest.ResponseRecorder {
		return corrDo(h, l, "POST", fmt.Sprintf("/api/accounts/%d/link", ids["acct:okta:alice"]),
			fmt.Sprintf(`{"identity_id":%d,"reason":"x"}`, ids["bob"]))
	}
	merge := func(l authtest.Login) *httptest.ResponseRecorder {
		return corrDo(h, l, "POST", fmt.Sprintf("/api/identities/%d/merge", ids["bob"]),
			fmt.Sprintf(`{"into":%d,"reason":"x"}`, ids["alice"]))
	}
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RoleTenantAdmin} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		if rec := link(l); rec.Code != 403 {
			t.Errorf("%s link: %d", role, rec.Code)
		}
		if rec := merge(l); rec.Code != 403 {
			t.Errorf("%s merge: %d", role, rec.Code)
		}
		if rec := corrDo(h, l, "GET", "/api/correlation/queue", ""); role != auth.RoleTenantAdmin && rec.Code != 200 {
			t.Errorf("%s queue: %d", role, rec.Code)
		}
	}
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := link(stale); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale link: %d %s", rec.Code, rec.Body)
	}
	if rec := merge(stale); rec.Code != 401 {
		t.Errorf("stale merge: %d", rec.Code)
	}
}

// Tenant B cannot read, undo, or link to tenant A's rows: A's ids answer
// exactly like missing ones.
func TestCorrelationAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	la := policyAdmin(t, f, f.A.ID, "pa@a.example")
	la2 := policyAdmin(t, f, f.A.ID, "pa2@a.example")
	lb := policyAdmin(t, f, f.B.ID, "pa@b.example")
	rec := corrDo(h, la, "POST", fmt.Sprintf("/api/identities/%d/merge", f.A.IDs["bob"]),
		fmt.Sprintf(`{"into":%d,"reason":"dup"}`, f.A.IDs["alice"]))
	if rec.Code != 202 {
		t.Fatalf("A merge request: %d %s", rec.Code, rec.Body)
	}
	var pend struct {
		Request mergeRequestView `json:"request"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pend)
	if rec = corrDo(h, la2, "POST", "/api/identity-merge-requests/"+pend.Request.ID+"/approve", `{}`); rec.Code != 200 {
		t.Fatalf("A merge approval: %d %s", rec.Code, rec.Body)
	}
	var appr struct {
		Merge mergeView `json:"merge"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &appr)
	m := appr.Merge
	before := storetest.Dump(t, f.DB, f.A.ID)

	cross := corrDo(h, lb, "POST", "/api/identity-merges/"+m.ID+"/unmerge", `{"reason":"x"}`)
	missing := corrDo(h, lb, "POST", "/api/identity-merges/00000000-0000-4000-8000-00000000dead/unmerge", `{"reason":"x"}`)
	if cross.Code != 404 || cross.Body.String() != missing.Body.String() {
		t.Errorf("B unmerging A's merge: %d %s (missing: %s)", cross.Code, cross.Body, missing.Body)
	}
	// B's account linked to A's identity: as for a missing identity
	acct := f.B.IDs["acct:okta:alice"]
	cross = corrDo(h, lb, "POST", fmt.Sprintf("/api/accounts/%d/link", acct), fmt.Sprintf(`{"identity_id":%d,"reason":"x"}`, f.A.IDs["carol"]))
	missing = corrDo(h, lb, "POST", fmt.Sprintf("/api/accounts/%d/link", acct), `{"identity_id":999999,"reason":"x"}`)
	if cross.Code != 404 || cross.Body.String() != missing.Body.String() {
		t.Errorf("link to A's identity: %d %s (missing: %s)", cross.Code, cross.Body, missing.Body)
	}
	cross = corrDo(h, lb, "POST", fmt.Sprintf("/api/identities/%d/merge", f.B.IDs["bob"]), fmt.Sprintf(`{"into":%d,"reason":"x"}`, f.A.IDs["carol"]))
	missing = corrDo(h, lb, "POST", fmt.Sprintf("/api/identities/%d/merge", f.B.IDs["bob"]), `{"into":999999,"reason":"x"}`)
	if cross.Code != 404 || cross.Body.String() != missing.Body.String() {
		t.Errorf("merge into A's identity: %d %s (missing: %s)", cross.Code, cross.Body, missing.Body)
	}
	if rec := corrDo(h, lb, "GET", "/api/identity-merges", ""); strings.Contains(rec.Body.String(), m.ID) {
		t.Error("B lists A's merge")
	}
	if after := storetest.Dump(t, f.DB, f.A.ID); after != before {
		t.Error("B's requests changed tenant A")
	}
}
