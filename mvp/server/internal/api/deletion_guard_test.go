package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
)

// The deletion threshold guard through the API (internal/deleteguard).

func guardPolicy(cat string, count int, mode string) string {
	return fmt.Sprintf(`{"type":"deletion_guard.update","payload":{"policies":[{"category":%q,"max_count":%d,"window_minutes":60,"mode":%q}]}}`, cat, count, mode)
}

func TestDeletionGuardAPI_DefaultsThenHoldAndRelease(t *testing.T) {
	e := newPrivEnv(t)
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)

	// on by default for every category
	g := e.admin.call("GET", "/api/admin/deletion-guard", "", 200)
	cats := g["categories"].([]any)
	if len(cats) != 5 {
		t.Fatalf("categories = %v", cats)
	}
	for _, c := range cats {
		m := c.(map[string]any)
		if m["mode"] != "hold_excess" || m["default"] != true {
			t.Errorf("category %v is not on by default", m)
		}
	}
	if cats[0].(map[string]any)["limit"] != float64(25) {
		t.Errorf("groups limit = %v", cats[0].(map[string]any)["limit"])
	}

	// tightening takes one admin and applies at once
	ch := e.admin.call("POST", "/api/admin/change-requests", guardPolicy("groups", 2, "hold_excess"), 201)
	if ch["status"] != "applied" || ch["two_person"] != false {
		t.Fatalf("tighten = %v", ch)
	}
	app := e.admin.folder("", "app")
	var gs []string
	for i := 0; i < 5; i++ {
		gs = append(gs, e.admin.group(app, fmt.Sprintf("g%d", i)))
	}
	e.admin.call("DELETE", "/api/groups/"+gs[0], "", 200)
	e.admin.call("DELETE", "/api/groups/"+gs[1], "", 200)
	held := e.admin.call("DELETE", "/api/groups/"+gs[2], "", 202)
	if held["held"] != float64(1) || held["applied"] != float64(0) || held["hold_id"] == "" || held["deleted"] != false ||
		!strings.Contains(held["message"].(string), "held for approval") || held["threshold"] != "2 per hour" {
		t.Fatalf("held delete = %v", held)
	}
	if got := e.admin.call("GET", "/api/groups/"+gs[2], "", 200); got["status"] != "active" {
		t.Errorf("the held group is %v", got["status"])
	}
	holdID := held["hold_id"].(string)

	// the usage shows the window
	g = e.admin.call("GET", "/api/admin/deletion-guard", "", 200)
	if u := g["categories"].([]any)[0].(map[string]any); u["used"] != float64(2) || u["remaining"] != float64(0) || g["open_holds"] != float64(1) {
		t.Errorf("usage = %v open %v", u, g["open_holds"])
	}
	// the hold, with its items and why
	one := e.admin.call("GET", "/api/admin/deletion-holds/"+holdID, "", 200)
	items := one["items"].([]any)
	if one["category"] != "groups" || one["status"] != "held" || len(items) != 1 || items[0].(map[string]any)["label"] != "app:g2" ||
		one["source"] != "user" || one["reason"].(map[string]any)["limit"] != float64(2) {
		t.Fatalf("hold = %v", one)
	}
	if l := e.admin.call("GET", "/api/admin/deletion-holds?status=held", "", 200)["holds"].([]any); len(l) != 1 {
		t.Errorf("held list = %v", l)
	}
	// the requester may not release their own held deletion; a different admin may
	if got := e.admin.call("POST", "/api/admin/deletion-holds/"+holdID+"/approve", "", 403); got["error"] != "same_actor" {
		t.Errorf("same actor approve = %v", got)
	}
	if got := e.admin.call("GET", "/api/groups/"+gs[2], "", 200); got["status"] != "active" {
		t.Errorf("the group changed on a refused release")
	}
	res := admin2.call("POST", "/api/admin/deletion-holds/"+holdID+"/approve", "", 200)
	if res["status"] != "released" || res["released"] != float64(1) {
		t.Fatalf("release = %v", res)
	}
	if got := e.admin.call("GET", "/api/groups/"+gs[2], "", 200); got["status"] != "deleted" {
		t.Errorf("the released group is %v", got["status"])
	}
	// the release was an override: the window did not grow, so the next delete is still held
	e.admin.call("DELETE", "/api/groups/"+gs[3], "", 202)
	e.admin.call("POST", "/api/admin/deletion-holds/"+holdID+"/approve", "", 409)

	// a discard keeps the group
	l := admin2.call("GET", "/api/admin/deletion-holds?status=held", "", 200)["holds"].([]any)
	did := l[0].(map[string]any)["id"].(string)
	if d := admin2.call("POST", "/api/admin/deletion-holds/"+did+"/discard", `{"note":"mistake"}`, 200); d["status"] != "discarded" {
		t.Errorf("discard = %v", d)
	}
	if got := e.admin.call("GET", "/api/groups/"+gs[3], "", 200); got["status"] != "active" {
		t.Errorf("a discarded hold deleted the group")
	}

	// loosening a safety setting takes a second admin
	ch = e.admin.call("POST", "/api/admin/change-requests", guardPolicy("groups", 100, "hold_excess"), 201)
	if ch["status"] != "pending_approval" || ch["two_person"] != true {
		t.Fatalf("loosen = %v", ch)
	}
	cid := ch["id"].(string)
	if g := e.admin.call("GET", "/api/admin/deletion-guard", "", 200); g["categories"].([]any)[0].(map[string]any)["limit"] != float64(2) {
		t.Errorf("the threshold changed before the approval")
	}
	admin2.call("POST", "/api/admin/change-requests/"+cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, ch["payload_hash"]), 200)
	if g := e.admin.call("GET", "/api/admin/deletion-guard", "", 200); g["categories"].([]any)[0].(map[string]any)["limit"] != float64(100) {
		t.Errorf("the threshold is %v after the approval", g["categories"].([]any)[0])
	}
	// a bad policy is refused
	e.admin.call("POST", "/api/admin/change-requests", `{"type":"deletion_guard.update","payload":{"policies":[{"category":"nope","max_count":1,"window_minutes":60,"mode":"hold_all"}]}}`, 422)

	// the other tenant sees none of it
	other := newGrpOn(t, e)
	if l := other.call("GET", "/api/admin/deletion-holds", "", 200)["holds"]; l != nil && len(l.([]any)) != 0 {
		t.Errorf("another tenant lists %v", l)
	}
	other.call("GET", "/api/admin/deletion-holds/"+holdID, "", 404)
	other.call("POST", "/api/admin/deletion-holds/"+holdID+"/discard", "", 404)
}

func TestDeletionGuardAPI_MembersAndBatch(t *testing.T) {
	e := newPrivEnv(t)
	e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil) // two active admins: no bootstrap restriction
	e.admin.call("POST", "/api/admin/change-requests", guardPolicy("group_members", 2, "hold_excess"), 201)
	app := e.admin.folder("", "app")
	g := e.admin.group(app, "g")
	var ids []int64
	for _, n := range []string{"alice", "bob", "carol", "dave"} {
		id := e.ident(n)
		ids = append(ids, id)
		e.admin.call("POST", "/api/groups/"+g+"/members", fmt.Sprintf(`{"identity":%d}`, id), 201)
	}
	// one removal at a time: the third is held
	e.admin.call("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", g, ids[0]), "", 200)
	e.admin.call("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", g, ids[1]), "", 200)
	held := e.admin.call("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", g, ids[2]), "", 202)
	if held["held"] != float64(1) || held["hold_id"] == "" {
		t.Fatalf("held removal = %v", held)
	}
	// a batch: both removals are held, in one hold
	b, _ := e.admin.post("POST", "/api/groups/"+g+"/members:batch", fmt.Sprintf(`{"atomic":false,"remove":["%d","%d"]}`, ids[2], ids[3]), 202)
	if b["held"] != float64(2) || b["removed"] != float64(0) {
		t.Fatalf("batch = %v", b)
	}
	if st := b["results"].([]any)[0].(map[string]any)["status"]; st != "held" {
		t.Errorf("batch item status = %v", st)
	}
	holds := e.admin.call("GET", "/api/admin/deletion-holds?category=group_members", "", 200)["holds"].([]any)
	if len(holds) != 2 {
		t.Fatalf("%d holds, want one per request", len(holds))
	}
	e.admin.call("GET", "/api/groups/"+g+"/members", "", 200)
}
