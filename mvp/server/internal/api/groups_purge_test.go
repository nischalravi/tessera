package api

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Purging a deleted group and deleting a folder with everything in it.

func blockerCodesOf(m map[string]any) []string {
	var out []string
	for _, b := range m["blockers"].([]any) {
		x := b.(map[string]any)
		out = append(out, x["kind"].(string)+":"+x["code"].(string))
	}
	return out
}

func TestGroupsAPI_PurgeDeletedGroup(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g := e.admin.group(app, "g")
	parent := e.admin.group(app, "parent")
	e.admin.call("POST", "/api/groups/"+parent+"/members", `{"group":"`+g+`"}`, 201)

	op := e.user("op", "carol")
	denied(t, op, "POST", "/api/groups/"+g+"/purge", `{"reason":"tidy up"}`, "admin")
	e.grant("/api/groups/"+g, "admin", "carol", "")
	// purge and recursive delete need a reason
	e.admin.call("POST", "/api/groups/"+g+"/purge", "", 422)
	// only a deleted group is purged
	if got := e.admin.call("POST", "/api/groups/"+g+"/purge", `{"reason":"tidy up"}`, 409); got["error"] != "not_deleted" {
		t.Errorf("purge of an active group = %v", got)
	}
	e.admin.call("DELETE", "/api/groups/"+g, `{"reason":"retired"}`, 200)
	// the deleter shows up, in the list and on the group
	dg := e.admin.call("GET", "/api/groups/"+g, "", 200)
	if dg["deleted_by"] != "admin@b.example (tenant admin)" && !strings.HasSuffix(fmt.Sprint(dg["deleted_by"]), "(tenant admin)") || dg["deleted_reason"] != "retired" || dg["deleted_at"] == nil || dg["deleted_with_folder"] != nil {
		t.Fatalf("deleted group = %v", dg)
	}
	// the deleter's name and reason are kept until a restore clears them
	e.admin.call("POST", "/api/groups/"+g+"/restore", "", 200)
	rg := e.admin.call("GET", "/api/groups/"+g, "", 200)
	if rg["deleted_by"] != nil || rg["deleted_at"] != nil || rg["deleted_reason"] != nil {
		t.Fatalf("restored group still marked: %v", rg)
	}
	e.admin.call("DELETE", "/api/groups/"+g, "", 200) // no reason is fine for a soft delete
	if dg = e.admin.call("GET", "/api/groups/"+g, "", 200); dg["deleted_reason"] != nil || dg["deleted_by"] == nil {
		t.Fatalf("deleted again = %v", dg)
	}
	// the deleted group is listed on request, with its status, and blocks its folder with a message that says so
	items := e.admin.call("GET", "/api/groups/native?folder="+app+"&deleted=true", "", 200)["items"].([]any)
	var deleted int
	for _, it := range items {
		if it.(map[string]any)["status"] == "deleted" {
			deleted++
		}
	}
	if deleted != 1 {
		t.Errorf("deleted groups listed = %d of %v", deleted, items)
	}
	// another group still uses it as a member: refused, naming that group
	in := e.admin.call("POST", "/api/groups/"+g+"/purge", `{"reason":"tidy up"}`, 409)
	if in["error"] != "group_in_use" || !strings.Contains(fmt.Sprint(in["groups"]), "app:parent") {
		t.Fatalf("purge while used = %v", in)
	}
	e.admin.call("DELETE", "/api/groups/"+parent+"/members/"+g, "", 200)
	// an operator without admin on the group cannot purge it; one with admin can
	op.call("POST", "/api/groups/"+g+"/purge", `{"reason":"tidy up"}`, 200)
	e.admin.call("GET", "/api/groups/"+g, "", 404)
	e.admin.call("POST", "/api/groups/"+g+"/purge", `{"reason":"tidy up"}`, 404)
	// the group's name is free again and its sibling is untouched
	e.admin.group(app, "g")
	e.admin.call("GET", "/api/groups/"+parent, "", 200)
	// the other tenant's groups are not reachable
	other := newGrpOn(t, e)
	og := other.group(other.folder("", "app"), "g")
	other.call("DELETE", "/api/groups/"+og, "", 200)
	e.admin.call("POST", "/api/groups/"+og+"/purge", `{"reason":"tidy up"}`, 404)
	other.call("GET", "/api/groups/"+og, "", 200)
}

func newGrpOn(t *testing.T, e *privEnv) grpClient {
	t.Helper()
	l := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "admin@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	return grpClient{client{t, l.Handler(e.srv.Handler())}}
}

func TestGroupsAPI_FolderNotEmptyMessageCountsDeleted(t *testing.T) {
	c, _ := newGrp(t)
	app := c.folder("", "app")
	g := c.group(app, "g")
	c.call("DELETE", "/api/groups/"+g, "", 200)
	got := c.call("DELETE", "/api/groups/folders/"+app, "", 409)
	if got["error"] != "folder_not_empty" || got["deleted_groups"] != float64(1) ||
		!strings.Contains(got["detail"].(string), "1 group(s) (1 deleted, restore or purge it)") {
		t.Errorf("answer = %v", got)
	}
	// purge, then the folder goes
	c.call("POST", "/api/groups/"+g+"/purge", `{"reason":"tidy up"}`, 200)
	c.call("DELETE", "/api/groups/folders/"+app, "", 200)
}

func TestGroupsAPI_RecursiveFolderDelete(t *testing.T) {
	e := newPrivEnv(t)
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil) // two active admins: no bootstrap restriction
	app := e.admin.folder("", "app")
	sub := e.admin.folder(app, "sub")
	deep := e.admin.folder(sub, "deep")
	g1, g2 := e.admin.group(sub, "g1"), e.admin.group(deep, "g2")
	e.admin.call("DELETE", "/api/groups/"+g2, "", 200) // a deleted group goes too

	// the flag is validated; the plan says what goes
	e.admin.call("DELETE", "/api/groups/folders/"+app+"?recursive=maybe", "", 422)
	e.admin.call("DELETE", "/api/groups/folders/"+app+"?recursive=true", "", 422) // a reason is required
	plan := e.admin.call("GET", "/api/groups/folders/"+app+"/delete-plan", "", 200)
	if plan["folders"] != float64(2) || plan["groups"] != float64(2) || plan["active_groups"] != float64(1) || plan["deleted_groups"] != float64(1) ||
		plan["needs_approval"] != false || plan["blocker_count"] != float64(0) {
		t.Fatalf("plan = %v", plan)
	}
	// a stale sign-in is asked for a step-up before anything is read or removed
	stale := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	sc := grpClient{client{t, stale.Handler(e.srv.Handler())}}
	rec := sc.do("DELETE", "/api/groups/folders/"+app+"?recursive=true", `{"reason":"tidy up"}`)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Fatalf("stale session = %d %s", rec.Code, rec.Body.String())
	}
	e.admin.call("GET", "/api/groups/folders/"+deep, "", 200)

	// used from outside the tree: refused, with who blocks and why
	keep := e.admin.folder("", "keep")
	out := e.admin.group(keep, "outside")
	e.admin.call("POST", "/api/groups/"+out+"/members", `{"group":"`+g1+`"}`, 201)
	got := e.admin.call("DELETE", "/api/groups/folders/"+app+"?recursive=true", `{"reason":"tidy up"}`, 409)
	if got["error"] != "recursive_delete_blocked" || fmt.Sprint(blockerCodesOf(got)) != "[group:used_outside]" ||
		!strings.Contains(got["detail"].(string), "keep:outside") {
		t.Fatalf("outside use = %v", got)
	}
	if p := e.admin.call("GET", "/api/groups/folders/"+app+"/delete-plan", "", 200); p["blocker_count"] != float64(1) {
		t.Errorf("plan with a blocker = %v", p)
	}
	e.admin.call("DELETE", "/api/groups/"+out+"/members/"+g1, "", 200)

	// without stem_admin on the folder: 403
	bob := e.user("bob", "bob")
	denied(t, bob, "DELETE", "/api/groups/folders/"+app+"?recursive=true", `{"reason":"tidy up"}`, "stem_admin")
	// stem_admin on the top folder covers every folder below it (K5), so that is all it takes
	e.grant("/api/groups/folders/"+app, "stem_admin", "bob", "")
	// a group with members needs a second admin: 202, nothing is deleted yet
	e.admin.call("POST", "/api/groups/"+g1+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident("alice")), 201)
	acc := bob.call("DELETE", "/api/groups/folders/"+app+"?recursive=true", `{"reason":"tidy up"}`, 202)
	cid := acc["change_request_id"].(string)
	if acc["status"] != "pending_approval" || acc["type"] != "groups.folder.delete_recursive" || acc["folder_id"] != app {
		t.Fatalf("answer = %v", acc)
	}
	e.admin.call("GET", "/api/groups/folders/"+deep, "", 200)
	cr := e.admin.call("GET", "/api/admin/change-requests/"+cid, "", 200)
	if cr["two_person"] != true || !strings.Contains(cr["summary"].(string), `Delete folder "app" and everything in it`) {
		t.Fatalf("change request = %v", cr)
	}
	body := fmt.Sprintf(`{"payload_hash":%q}`, cr["payload_hash"])
	// a folder that grew since is refused, not deleted
	e.admin.group(deep, "late")
	if rec = admin2.do("POST", "/api/admin/change-requests/"+cid+"/approve", body); rec.Code != 409 || !strings.Contains(rec.Body.String(), "folder_changed") {
		t.Errorf("approving a stale request = %d %s", rec.Code, rec.Body.String())
	}
	e.admin.call("GET", "/api/groups/folders/"+deep, "", 200)
	// ask again for the current tree and approve it
	acc = bob.call("DELETE", "/api/groups/folders/"+app+"?recursive=true", `{"reason":"tidy up"}`, 202)
	cid = acc["change_request_id"].(string)
	cr = e.admin.call("GET", "/api/admin/change-requests/"+cid, "", 200)
	body = fmt.Sprintf(`{"payload_hash":%q}`, cr["payload_hash"])
	// the requester is not the approver; another admin approves and the tree goes
	if done := admin2.call("POST", "/api/admin/change-requests/"+cid+"/approve", body, 200); done["status"] != "applied" {
		t.Fatalf("approved request = %v", done)
	}
	for _, id := range []string{app, sub, deep} {
		e.admin.call("GET", "/api/groups/folders/"+id, "", 404)
	}
	e.admin.call("GET", "/api/groups/"+g1, "", 404)
	e.admin.folder("", "app") // the names are free again
	// the audit trail says who purged what with which folder
	if rec := e.admin.do("GET", "/api/audit?action=groups.group.purged&limit=50", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"with_folder":"app"`) ||
		!strings.Contains(rec.Body.String(), `"deleted_by":"Bob"`) {
		t.Errorf("purge events do not name the folder and the deleter: %d %.400s", rec.Code, rec.Body.String())
	}

	// a small tree without members is deleted at once, with the counts
	t1 := e.admin.folder("", "t1")
	e.admin.folder(t1, "t2")
	e.admin.group(t1, "x")
	res := e.admin.call("DELETE", "/api/groups/folders/"+t1+"?recursive=true", `{"reason":"tidy up"}`, 200)
	if res["deleted"] != true || res["folders"] != float64(2) || res["groups"] != float64(1) {
		t.Errorf("result = %v", res)
	}
	e.admin.call("GET", "/api/groups/folders/"+t1, "", 404)
	// another tenant's folder is not there
	other := newGrpOn(t, e)
	of := other.folder("", "theirs")
	e.admin.call("DELETE", "/api/groups/folders/"+of+"?recursive=true", `{"reason":"tidy up"}`, 404)
	e.admin.call("GET", "/api/groups/folders/"+of+"/delete-plan", "", 404)
	other.call("GET", "/api/groups/folders/"+of, "", 200)
}

func TestGroupsAPI_DeletedByIsTenantScoped(t *testing.T) {
	e := newPrivEnv(t)
	other := newGrpOn(t, e)
	og := other.group(other.folder("", "app"), "g")
	other.call("DELETE", "/api/groups/"+og, `{"reason":"theirs"}`, 200)
	e.admin.call("GET", "/api/groups/"+og, "", 404)
	if items := e.admin.call("GET", "/api/groups/native?deleted=true", "", 200)["items"].([]any); len(items) != 0 {
		t.Errorf("another tenant's deleted group is listed: %v", items)
	}
	if got := other.call("GET", "/api/groups/"+og, "", 200); got["deleted_reason"] != "theirs" {
		t.Errorf("their own group = %v", got)
	}
}
