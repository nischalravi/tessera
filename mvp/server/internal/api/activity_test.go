package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestActivityAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	bob := reqLogin(t, f, "bob@b.example", []auth.Role{auth.RoleViewer}, "bob")
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)

	for i := 0; i < 3; i++ {
		if rec := reqDo(h, alice, "POST", "/api/request-drafts", `{"justification":"note to self"}`); rec.Code != 201 {
			t.Fatalf("draft: %d %s", rec.Code, rec.Body)
		}
	}
	type row struct {
		Action     string  `json:"action"`
		Outcome    string  `json:"outcome"`
		OccurredAt string  `json:"occurred_at"`
		TargetType *string `json:"target_type"`
	}
	var mine []row
	rec := reqDo(h, alice, "GET", "/api/activity", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &mine); err != nil || rec.Code != 200 || len(mine) != 3 {
		t.Fatalf("alice: %d %s", rec.Code, rec.Body)
	}
	for _, r := range mine {
		if r.Action != "request.draft.save" || r.Outcome == "" || r.OccurredAt == "" {
			t.Errorf("row %+v", r)
		}
	}
	// the detail (here the draft id) and page reads are not part of the feed
	if strings.Contains(rec.Body.String(), "http.request") || strings.Contains(rec.Body.String(), "draft_id") {
		t.Errorf("feed shows more than it should: %s", rec.Body)
	}
	var one []row
	if rec := reqDo(h, alice, "GET", "/api/activity?limit=1", ""); json.Unmarshal(rec.Body.Bytes(), &one) != nil || len(one) != 1 {
		t.Errorf("limit=1: %s", rec.Body)
	}
	for q, want := range map[string]int{"?limit=0": 422, "?limit=abc": 422} {
		if rec := reqDo(h, alice, "GET", "/api/activity"+q, ""); rec.Code != want {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
	// nobody sees another person's, or another tenant's, activity
	for name, l := range map[string]authtest.Login{"bob": bob, "tenant A's admin": adminA} {
		var other []row
		rec := reqDo(h, l, "GET", "/api/activity", "")
		if err := json.Unmarshal(rec.Body.Bytes(), &other); err != nil || rec.Code != 200 || len(other) != 0 {
			t.Errorf("%s sees alice's activity: %d %s", name, rec.Code, rec.Body)
		}
	}
}
