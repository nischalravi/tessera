package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestRequestDraftsAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	bob := reqLogin(t, f, "bob@b.example", []auth.Role{auth.RoleViewer}, "bob")
	g := f.B.IDs["group:okta:platform"]

	rec := reqDo(h, alice, "POST", "/api/request-drafts", fmt.Sprintf(
		`{"beneficiary_ids":[%d],"items":[{"kind":"group","group_id":%d}],"duration_hours":24,"justification":"joining the platform team"}`, f.B.IDs["alice"], g))
	var d draftView
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || rec.Code != 201 || d.ID == "" || len(d.Items) != 1 || d.Items[0].Name == "" ||
		d.Items[0].System != "okta" || len(d.Beneficiaries) != 1 || d.Beneficiaries[0].Name == "" || d.DurationHours == nil || *d.DurationHours != 24 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}

	// it lists and resumes for alice, and is invisible to bob
	if rec := reqDo(h, alice, "GET", "/api/request-drafts", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), d.ID) {
		t.Errorf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, alice, "GET", "/api/request-drafts/"+d.ID, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "joining the platform team") {
		t.Errorf("get: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, bob, "GET", "/api/request-drafts", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), d.ID) {
		t.Errorf("bob's list: %d %s", rec.Code, rec.Body)
	}
	missing := "00000000-0000-4000-8000-00000000dead"
	for _, c := range []struct{ method, body string }{{"GET", ""}, {"PUT", `{"justification":"mine now"}`}, {"DELETE", ""}} {
		cross := reqDo(h, bob, c.method, "/api/request-drafts/"+d.ID, c.body)
		none := reqDo(h, bob, c.method, "/api/request-drafts/"+missing, c.body)
		if cross.Code != 404 || cross.Code != none.Code || cross.Body.String() != none.Body.String() {
			t.Errorf("bob %s alice's draft: %d %s, missing: %d %s", c.method, cross.Code, cross.Body, none.Code, none.Body)
		}
	}

	// saving again replaces it
	rec = reqDo(h, alice, "PUT", "/api/request-drafts/"+d.ID, `{"items":[],"justification":"changed my mind"}`)
	var d2 draftView
	if err := json.Unmarshal(rec.Body.Bytes(), &d2); err != nil || rec.Code != 200 || d2.ID != d.ID || len(d2.Items) != 0 || d2.Justification != "changed my mind" ||
		!d2.CreatedAt.Equal(d.CreatedAt) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}

	// a draft is a note: nothing was submitted
	if rec := reqDo(h, alice, "GET", "/api/requests", ""); strings.Contains(rec.Body.String(), `"id"`) {
		t.Errorf("a draft became a request: %s", rec.Body)
	}
	acts := reqAuditActions(t, f, f.B.ID)
	if acts["request.draft.save"] != 2 || acts["request.submit"] != 0 {
		t.Errorf("audit %v", acts)
	}

	if rec := reqDo(h, alice, "DELETE", "/api/request-drafts/"+d.ID, ""); rec.Code != 200 {
		t.Errorf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, alice, "GET", "/api/request-drafts/"+d.ID, ""); rec.Code != 404 {
		t.Errorf("get after delete: %d", rec.Code)
	}
	if acts := reqAuditActions(t, f, f.B.ID); acts["request.draft.delete"] != 1 {
		t.Errorf("audit %v", acts)
	}
}

func TestRequestDraftsAPI_InputAndTenancy(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	gB := f.B.IDs["group:okta:platform"]
	gA := f.A.IDs["group:okta:platform"]
	if gA == gB {
		t.Fatal("the fixture gave both tenants the same group id")
	}

	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"nothing to save":       {`{}`, 422},
		"unknown group":         {`{"items":[{"kind":"group","group_id":999999}]}`, 404},
		"another tenant group":  {fmt.Sprintf(`{"items":[{"kind":"group","group_id":%d}]}`, gA), 404},
		"unknown person":        {`{"beneficiary_ids":[999999]}`, 404},
		"another tenant person": {fmt.Sprintf(`{"beneficiary_ids":[%d]}`, f.A.IDs["alice"]), 404},
		"unknown role":          {`{"items":[{"kind":"role","role_id":"nope"}]}`, 404},
		"bad kind":              {`{"items":[{"kind":"user","group_id":1}]}`, 422},
		"group with role id":    {fmt.Sprintf(`{"items":[{"kind":"group","group_id":%d,"role_id":"x"}]}`, gB), 422},
		"duplicate item":        {fmt.Sprintf(`{"items":[{"kind":"group","group_id":%d},{"kind":"group","group_id":%d}]}`, gB, gB), 422},
		"duplicate person":      {fmt.Sprintf(`{"beneficiary_ids":[%d,%d]}`, f.B.IDs["alice"], f.B.IDs["alice"]), 422},
		"negative duration":     {`{"duration_hours":-1,"justification":"x"}`, 422},
		"huge duration":         {`{"duration_hours":100000,"justification":"x"}`, 422},
		"long justification":    {`{"justification":"` + strings.Repeat("x", 1001) + `"}`, 422},
		"unknown field":         {`{"justification":"x","submit":true}`, 422},
		"just a note":           {`{"justification":"remember to ask for this"}`, 201},
	} {
		if rec := reqDo(h, alice, "POST", "/api/request-drafts", tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, tc.want)
		}
	}
	// a bad id is a plain 404
	if rec := reqDo(h, alice, "GET", "/api/request-drafts/not-a-uuid", ""); rec.Code != 404 {
		t.Errorf("bad id: %d", rec.Code)
	}
	// another tenant's user sees none of it
	if rec := reqDo(h, adminA, "GET", "/api/request-drafts", ""); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("tenant A's list: %d %s", rec.Code, rec.Body)
	}
	// the cap: 50 drafts, then a refusal
	for i := 0; i < 49; i++ { // one exists already
		if rec := reqDo(h, alice, "POST", "/api/request-drafts", `{"justification":"note"}`); rec.Code != 201 {
			t.Fatalf("draft %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := reqDo(h, alice, "POST", "/api/request-drafts", `{"justification":"one too many"}`); rec.Code != 409 || !strings.Contains(rec.Body.String(), "too_many_drafts") {
		t.Errorf("51st draft: %d %s", rec.Code, rec.Body)
	}
}
