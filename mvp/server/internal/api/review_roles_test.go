package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Role memberships in reviews over the API (issue #214).
func TestReviewRolesAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	op := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator},
		IdentityID: ensureIdentity(t, f.DB, f.B.ID, "op-reviewer", "op-reviewer", storetest.Now)}, authtest.Phr, storetest.Now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	pa := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	opA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "op@a.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)

	ps, err := srv.policies()
	if err != nil {
		t.Fatal(err)
	}
	var roleID string
	var camp int64
	err = f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		res, err := roles.Create(c, roles.Spec{Name: "Engineer", Risk: "medium", Note: "t",
			Birthright:   &roles.Rule{Department: []string{"Engineering"}},
			Entitlements: []int64{f.B.IDs["group:okta:platform"]}}, roles.Actor{Display: "Pat"}, false, storetest.Now)
		if err != nil {
			return err
		}
		roleID = res.Role.ID
		camp, err = reviews.GenerateScopedCampaign(c, storetest.Now, "roles", 60, ps, reviews.Scope{RoleIDs: []string{roleID}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// the campaign lists memberships, with role and source
	rec := schedDo(h, viewer, "GET", fmt.Sprintf("/api/reviews/campaigns/%d", camp), "")
	var cv struct {
		Items []struct {
			ID           int64          `json:"id"`
			Kind         string         `json:"kind"`
			Role         map[string]any `json:"role"`
			MemberSource string         `json:"member_source"`
			Identity     struct {
				Name string `json:"name"`
			} `json:"identity"`
		} `json:"review_items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &cv)
	if rec.Code != 200 || len(cv.Items) != 2 || cv.Items[0].Kind != "membership" || cv.Items[0].Role["name"] != "Engineer" || cv.Items[0].MemberSource != "rule" {
		t.Fatalf("campaign: %d %s", rec.Code, rec.Body)
	}
	item := cv.Items[0].ID
	path := fmt.Sprintf("/api/reviews/items/%d/decision", item)

	// a rule member needs a choice
	if rec := schedDo(h, op, "POST", path, `{"decision":"revoke"}`); rec.Code != 422 {
		t.Fatalf("revoke without a choice: %d %s", rec.Code, rec.Body)
	}
	if rec := schedDo(h, op, "POST", path, `{"decision":"revoke","rule_action":"nuke"}`); rec.Code != 422 {
		t.Errorf("unknown rule_action: %d %s", rec.Code, rec.Body)
	}
	if rec := schedDo(h, op, "POST", path, `{"decision":"revoke","comment":"no longer needed","rule_action":"exclude"}`); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"resolution":"exclude"`) {
		t.Fatalf("exclude: %d %s", rec.Code, rec.Body)
	}

	// the exclusion list is versioned and readable
	rec = schedDo(h, viewer, "GET", "/api/roles/"+roleID+"/exclusions", "")
	var ex exclusionList
	_ = json.Unmarshal(rec.Body.Bytes(), &ex)
	if rec.Code != 200 || ex.Version != 1 || len(ex.Items) != 1 || !ex.Items[0].Active || ex.Items[0].ReviewItemID == nil || *ex.Items[0].ReviewItemID != item {
		t.Fatalf("exclusions: %d %s", rec.Code, rec.Body)
	}
	if rec := schedDo(h, viewer, "POST", "/api/roles/"+roleID+"/exclusions/1/remove", `{"reason":"x"}`); rec.Code != 403 {
		t.Errorf("viewer removes an exclusion: %d", rec.Code)
	}
	person := ex.Items[0].Person.ID
	rec = schedDo(h, pa, "POST", fmt.Sprintf("/api/roles/%s/exclusions/%d/remove", roleID, person), `{"reason":"back in"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"version":2`) {
		t.Fatalf("remove exclusion: %d %s", rec.Code, rec.Body)
	}
	rec = schedDo(h, pa, "POST", fmt.Sprintf("/api/roles/%s/exclusions/%d/remove", roleID, person), `{"reason":"again"}`)
	if rec.Code != 404 {
		t.Errorf("remove twice: %d %s", rec.Code, rec.Body)
	}
	if rec := schedDo(h, viewer, "GET", "/api/roles/"+roleID+"/flags", ""); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("flags: %d %s", rec.Code, rec.Body)
	}

	// the other person: flag
	other := cv.Items[1].ID
	if rec := schedDo(h, op, "POST", fmt.Sprintf("/api/reviews/items/%d/decision", other), `{"decision":"revoke","rule_action":"flag"}`); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"resolution":"flag"`) {
		t.Fatalf("flag: %d %s", rec.Code, rec.Body)
	}
	if rec := schedDo(h, viewer, "GET", "/api/roles/"+roleID+"/flags", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), fmt.Sprintf(`"item_id":%d`, other)) {
		t.Errorf("flags: %d %s", rec.Code, rec.Body)
	}

	// a schedule scoped to roles
	first := storetest.Now.Add(24 * 3600e9).UTC().Format("2006-01-02T15:04:05Z")
	sched := fmt.Sprintf(`{"name":"Roles","recurrence":"quarterly","first_run_at":"%s","role_ids":["%s"]}`, first, roleID)
	rec = schedDo(h, op, "POST", "/api/reviews/schedules", sched)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"role_ids":["`+roleID+`"]`) {
		t.Fatalf("scoped schedule: %d %s", rec.Code, rec.Body)
	}
	var sv scheduleView
	_ = json.Unmarshal(rec.Body.Bytes(), &sv)
	if rec := schedDo(h, op, "POST", "/api/reviews/schedules", strings.Replace(sched, roleID, "no-such-role", 1)); rec.Code != 422 ||
		!strings.Contains(rec.Body.String(), "invalid_roles") {
		t.Errorf("unknown role: %d %s", rec.Code, rec.Body)
	}
	// an update without role_ids keeps the scope; an empty list clears it
	rec = schedDo(h, op, "PUT", "/api/reviews/schedules/"+sv.ID, `{"name":"Roles","recurrence":"quarterly"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"role_ids":["`+roleID+`"]`) {
		t.Errorf("update keeps scope: %d %s", rec.Code, rec.Body)
	}
	rec = schedDo(h, op, "PUT", "/api/reviews/schedules/"+sv.ID, `{"name":"Roles","recurrence":"quarterly","role_ids":[]}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"role_ids":[]`) {
		t.Errorf("clear scope: %d %s", rec.Code, rec.Body)
	}

	// another tenant sees nothing of it
	cross := schedDo(h, opA, "GET", "/api/roles/"+roleID+"/exclusions", "")
	missing := schedDo(h, opA, "GET", "/api/roles/00000000-0000-4000-8000-00000000dead/exclusions", "")
	if cross.Code != 404 || cross.Body.String() != missing.Body.String() {
		t.Errorf("cross-tenant exclusions: %d %s vs %d %s", cross.Code, cross.Body, missing.Code, missing.Body)
	}
}
