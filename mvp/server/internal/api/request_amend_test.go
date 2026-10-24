package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Amending a pending request over the API: who may, the caps, the audit trail and tenant isolation.
func TestRequestAmendAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	lines := seedRequestLines(t, f)
	id := lines[f.B.ID]
	base := "/api/requests/" + id
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	outsider := reqLogin(t, f, "o@b.example", []auth.Role{auth.RoleViewer}, "alice")
	tenantA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)

	if rec := reqDo(h, admin, "POST", base+"/comments", `{"body":"checked with the team"}`); rec.Code != 201 || !strings.Contains(rec.Body.String(), "checked with the team") {
		t.Fatalf("comment: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", base+"/comments", `{"body":" "}`); rec.Code != 422 || strings.Contains(rec.Body.String(), `"body"`) {
		t.Errorf("empty comment: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, outsider, "POST", base+"/comments", `{"body":"hi"}`); rec.Code != 404 {
		t.Errorf("a person with no part in the request comments: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "GET", base+"/comments", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "checked with the team") {
		t.Errorf("list comments: %d %s", rec.Code, rec.Body)
	}
	att := `{"name":"ticket.pdf","content_type":"application/pdf","size_bytes":2048,"reference":"TKT-1"}`
	if rec := reqDo(h, admin, "POST", base+"/attachments", att); rec.Code != 422 || !strings.Contains(rec.Body.String(), "attachments_not_allowed") {
		t.Errorf("attachments off: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "GET", "/api/request-settings", ""); rec.Code != 200 {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "PUT", "/api/request-settings", `{"version":0,"justification_required":true,"justification_min_length":1,"attachments_allowed":true,"history_visibility":"readers","for_others":"permission"}`); rec.Code != 200 {
		t.Fatalf("turn attachments on: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", base+"/attachments", att); rec.Code != 201 || !strings.Contains(rec.Body.String(), "ticket.pdf") {
		t.Errorf("attach: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", base+"/attachments", `{"name":"big","size_bytes":99999999}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "attachment_too_large") {
		t.Errorf("oversize: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "GET", base+"/attachments", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "ticket.pdf") || !strings.Contains(rec.Body.String(), "max_bytes") {
		t.Errorf("list attachments: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "GET", base, ""); !strings.Contains(rec.Body.String(), `"can_amend":true`) {
		t.Errorf("can_amend: %s", rec.Body)
	}
	// the line is routed to a decider only (no stages), so an approver cannot be added to it
	if rec := reqDo(h, admin, "POST", base+"/approvers", fmt.Sprintf(`{"identity_id":%d,"reason":"second look"}`, f.B.IDs["carol"])); rec.Code != 409 || !strings.Contains(rec.Body.String(), "no_stages") {
		t.Errorf("add approver without stages: %d %s", rec.Code, rec.Body)
	}

	// tenant A reaches nothing of B's, exactly as for a missing line
	for _, c := range []struct{ method, suffix, body string }{
		{"GET", "/comments", ""}, {"POST", "/comments", `{"body":"x"}`}, {"GET", "/attachments", ""}, {"POST", "/attachments", att},
		{"POST", "/approvers", `{"identity_id":1,"reason":"x"}`},
	} {
		cross := reqDo(h, tenantA, c.method, base+c.suffix, c.body)
		missing := reqDo(h, tenantA, c.method, "/api/requests/00000000-0000-4000-8000-00000000dead"+c.suffix, c.body)
		if cross.Code != 404 || cross.Body.String() != missing.Body.String() {
			t.Errorf("%s %s: %d %s (missing: %s)", c.method, c.suffix, cross.Code, cross.Body, missing.Body)
		}
	}
	acts := reqAuditActions(t, f, f.B.ID)
	if acts["request.comment.added"] != 1 || acts["request.attachment.added"] != 1 {
		t.Errorf("audit: %v", acts)
	}
}
