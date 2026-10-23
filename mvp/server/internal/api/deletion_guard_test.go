package api

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// The deletion threshold guard through the API (internal/deleteguard).

func guardPolicy(cat string, count int, mode string) string {
	return fmt.Sprintf(`{"type":"deletion_guard.update","payload":{"policies":[{"category":%q,"max_count":%d,"window_minutes":60,"mode":%q}]}}`, cat, count, mode)
}

// setGuard saves a policy as admin and, when it needs a second admin (a hold_excess category that was never
// set loosens what source-driven runs get, #468), has approver approve it.
func setGuard(admin, approver grpClient, body string) {
	ch := admin.call("POST", "/api/admin/change-requests", body, 201)
	if ch["status"] == "pending_approval" {
		approver.call("POST", "/api/admin/change-requests/"+ch["id"].(string)+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, ch["payload_hash"]), 200)
	}
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
	ch := e.admin.call("POST", "/api/admin/change-requests", guardPolicy("groups", 2, "hold_all"), 201)
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
	a2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil) // two active admins: no bootstrap restriction
	setGuard(e.admin, a2, guardPolicy("group_members", 2, "hold_excess"))
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

func TestDeletionGuardAPI_BulkActionJoinsOneHold(t *testing.T) {
	e := newPrivEnv(t)
	a2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	setGuard(e.admin, a2, guardPolicy("groups", 1, "hold_excess"))
	app := e.admin.folder("", "app")
	batch := "0b1d4f2a-5c1e-4a55-9a53-6a3f4f9d2c11"
	var holds = map[string]bool{}
	for i := 0; i < 4; i++ {
		id := e.admin.group(app, fmt.Sprintf("g%d", i))
		rec := e.admin.do("DELETE", "/api/groups/"+id, "", "X-Deletion-Batch", batch)
		if i == 0 && rec.Code != 200 {
			t.Fatalf("first delete = %d %s", rec.Code, rec.Body.String())
		}
		if i > 0 {
			if rec.Code != 202 {
				t.Fatalf("delete %d = %d %s", i, rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			holds[fmt.Sprint(body["hold_id"])] = true
		}
	}
	if len(holds) != 1 {
		t.Errorf("the bulk action made %d holds, want 1", len(holds))
	}
	l := e.admin.call("GET", "/api/admin/deletion-holds?status=held", "", 200)["holds"].([]any)
	if len(l) != 1 || l[0].(map[string]any)["item_count"] != float64(3) {
		t.Errorf("holds = %v", l)
	}
}

// The release of holds that sources made (a sync, an import, a leaver feed) goes through the
// same routes: the API knows how to apply every kind of held item.
func TestDeletionGuardAPI_ReleasesSyncHolds(t *testing.T) {
	e := newPrivEnv(t)
	e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	feed := func(status string) *connectors.DiscoveryResult {
		r := &connectors.DiscoveryResult{}
		for i := 0; i < 20; i++ {
			x := fmt.Sprintf("api-guard-%02d", i)
			r.Identities = append(r.Identities, connectors.IdentityRecord{ExternalID: x, Name: "P " + x, Type: "human", Status: status})
		}
		return r
	}
	sync := func(at time.Time, status string) {
		t.Helper()
		if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
			_, err := ingest.Discovery(c, at, []*connectors.DiscoveryResult{feed(status)}, false)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	sync(storetest.Now, "active")
	sync(storetest.Now.Add(time.Minute), "terminated")
	holds := e.admin.call("GET", "/api/admin/deletion-holds?category=identities&status=held", "", 200)["holds"].([]any)
	if len(holds) != 1 || holds[0].(map[string]any)["source"] != "connector" || holds[0].(map[string]any)["item_count"] != float64(20) {
		t.Fatalf("holds = %v", holds)
	}
	id := holds[0].(map[string]any)["id"].(string)
	one := e.admin.call("GET", "/api/admin/deletion-holds/"+id, "", 200)
	if its := one["items"].([]any); len(its) != 20 || !strings.Contains(its[0].(map[string]any)["label"].(string), "set to terminated") {
		t.Fatalf("items = %v", one["items"])
	}
	// release only two of them: the rest is discarded
	res := e.admin.call("POST", "/api/admin/deletion-holds/"+id+"/approve", `{"items":[0,1]}`, 200)
	if res["status"] != "partially_released" || res["released"] != float64(2) || res["discarded"] != float64(18) {
		t.Fatalf("partial release = %v", res)
	}
	ended := 0
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
		for i := 0; i < 20; i++ {
			if p, err := c.IdentityByExternalID(fmt.Sprintf("api-guard-%02d", i)); err != nil {
				return err
			} else if p.Status != "active" {
				ended++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if ended != 2 { // a source-driven run applies none by default; two were released
		t.Errorf("%d identities ended, want 2", ended)
	}
}

func srcChange(src string) string {
	return `{"type":"deletion_guard.update","payload":{"sources":[` + src + `]}}`
}

func TestDeletionGuardAPI_PerSourceSettings(t *testing.T) {
	e := newPrivEnv(t)
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	conn := store.NewID()
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
		return c.InsertConnection(&store.Connection{ID: conn, Name: "Workday prod", ConnectorType: "workday", System: "workday",
			Role: "account_source", CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	path := "/api/admin/deletion-guard/sources/connection/" + conn
	one := func(cat, rest string) string {
		return fmt.Sprintf(`{"kind":"connection","source_id":%q,"category":%q%s}`, conn, cat, rest)
	}
	catOf := func(v map[string]any, cat string) map[string]any {
		for _, c := range v["categories"].([]any) {
			if c.(map[string]any)["category"] == cat {
				return c.(map[string]any)
			}
		}
		t.Fatalf("no category %s in %v", cat, v)
		return nil
	}

	v := e.admin.call("GET", path, "", 200)
	if v["name"] != "Workday prod" || len(v["categories"].([]any)) != 2 || catOf(v, "identities")["override"] != nil {
		t.Fatalf("source view = %v", v)
	}
	eff := catOf(v, "identities")["effective"].(map[string]any)
	if eff["mode"] != "hold_all" || eff["feed"].(map[string]any)["drop_percent"] != float64(20) || eff["feed"].(map[string]any)["empty_check"] != true {
		t.Errorf("effective before any override = %v", eff)
	}
	e.admin.call("GET", "/api/admin/deletion-guard/sources/connection/nope", "", 404)
	e.admin.call("GET", "/api/admin/deletion-guard/sources/tenant/x", "", 404)

	// a tighter threshold takes one admin and applies at once
	ch := e.admin.call("POST", "/api/admin/change-requests", srcChange(one("identities", `,"mode":"hold_all","max_count":3,"window_minutes":60`)), 201)
	if ch["status"] != "applied" || ch["two_person"] != false {
		t.Fatalf("tighten = %v", ch)
	}
	v = e.admin.call("GET", path, "", 200)
	if o := catOf(v, "identities")["override"].(map[string]any); o["mode"] != "hold_all" || o["max_count"] != float64(3) || catOf(v, "identities")["limit"] != float64(3) {
		t.Errorf("override = %v", catOf(v, "identities"))
	}
	// a stricter feed check is one admin; a looser one needs two
	if ch = e.admin.call("POST", "/api/admin/change-requests", srcChange(one("identities", `,"mode":"hold_all","max_count":3,"window_minutes":60,"feed_drop_percent":10`)), 201); ch["status"] != "applied" {
		t.Fatalf("stricter feed = %v", ch)
	}
	ch = e.admin.call("POST", "/api/admin/change-requests", srcChange(one("identities", `,"mode":"hold_all","max_count":3,"window_minutes":60,"feed_drop_percent":60,"feed_empty_check":false`)), 201)
	if ch["status"] != "pending_approval" || ch["two_person"] != true {
		t.Fatalf("looser feed = %v", ch)
	}
	if o := catOf(e.admin.call("GET", path, "", 200), "identities")["override"].(map[string]any); o["feed_drop_percent"] != float64(10) {
		t.Errorf("the feed setting changed before the approval: %v", o)
	}
	admin2.call("POST", "/api/admin/change-requests/"+ch["id"].(string)+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, ch["payload_hash"]), 200)
	o := catOf(e.admin.call("GET", path, "", 200), "identities")["override"].(map[string]any)
	if o["feed_drop_percent"] != float64(60) || o["feed_empty_check"] != false {
		t.Errorf("override after approval = %v", o)
	}
	// a feed-only override for another category (the mode is inherited) that loosens is two-admin too
	if ch = e.admin.call("POST", "/api/admin/change-requests", srcChange(one("accounts", `,"feed_drop_percent":50`)), 201); ch["two_person"] != true {
		t.Errorf("feed-only loosening = %v", ch)
	}
	// removing the override puts the category's settings back: here they are looser, so it takes two admins
	rm := e.admin.call("POST", "/api/admin/change-requests", srcChange(one("identities", `,"remove":true`)), 201)
	if rm["status"] != "pending_approval" {
		t.Errorf("removing an override that was tighter than the category: %v", rm)
	}
	admin2.call("POST", "/api/admin/change-requests/"+rm["id"].(string)+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, rm["payload_hash"]), 200)
	if catOf(e.admin.call("GET", path, "", 200), "identities")["override"] != nil {
		t.Error("the override is still there")
	}
	// the list on Admin → Deletion guard names the sources
	e.admin.call("POST", "/api/admin/change-requests", srcChange(one("identities", `,"mode":"hold_all","max_count":2,"window_minutes":60`)), 201)
	g := e.admin.call("GET", "/api/admin/deletion-guard", "", 200)
	srcs := g["sources"].([]any)
	if len(srcs) != 1 || srcs[0].(map[string]any)["name"] != "Workday prod" || srcs[0].(map[string]any)["kind"] != "connection" {
		t.Errorf("sources = %v", srcs)
	}
	// refused: an unknown source, a kind with no settings yet, a removal of nothing, bad numbers, a duplicate
	e.admin.call("POST", "/api/admin/change-requests", srcChange(`{"kind":"connection","source_id":"nope","category":"accounts","mode":"hold_all","max_count":1,"window_minutes":60}`), 422)
	e.admin.call("POST", "/api/admin/change-requests", srcChange(`{"kind":"scim_client","source_id":"x","category":"accounts","mode":"hold_all","max_count":1,"window_minutes":60}`), 422)
	e.admin.call("POST", "/api/admin/change-requests", srcChange(one("accounts", `,"remove":true`)), 422)
	e.admin.call("POST", "/api/admin/change-requests", srcChange(one("accounts", `,"feed_drop_percent":101`)), 422)
	e.admin.call("POST", "/api/admin/change-requests", srcChange(one("accounts", `,"mode":"hold_all"`)), 422)
	e.admin.call("POST", "/api/admin/change-requests", srcChange(one("accounts", `,"feed_drop_percent":5`)+","+one("accounts", `,"feed_drop_percent":6`)), 422)

	// the other tenant does not see this source
	other := newGrpOn(t, e)
	other.call("GET", path, "", 404)
	if s := other.call("GET", "/api/admin/deletion-guard", "", 200)["sources"].([]any); len(s) != 0 {
		t.Errorf("another tenant lists %v", s)
	}
}

// The Inbox shows a held deletion to the tenant admins while it waits, and the task closes with the hold.
func TestDeletionGuardAPI_InboxTaskFollowsTheHold(t *testing.T) {
	e := newPrivEnv(t)
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	setGuard(e.admin, admin2, guardPolicy("groups", 1, "hold_excess"))
	app := e.admin.folder("", "app")
	var gs []string
	for i := 0; i < 3; i++ {
		gs = append(gs, e.admin.group(app, fmt.Sprintf("g%d", i)))
	}
	e.admin.call("DELETE", "/api/groups/"+gs[0], "", 200)
	held := e.admin.call("DELETE", "/api/groups/"+gs[1], "", 202)
	holdID := held["hold_id"].(string)
	tasks := func(who grpClient, status string) []map[string]any {
		var out []map[string]any
		for _, x := range who.call("GET", "/api/groups/inbox/tasks?kind=deletion_held&status="+status, "", 200)["items"].([]any) {
			out = append(out, x.(map[string]any))
		}
		return out
	}
	ts := tasks(e.admin, "open")
	if len(ts) != 1 || ts[0]["object_type"] != "deletion_hold" || ts[0]["object_id"] != holdID || ts[0]["kind"] != "deletion_held" {
		t.Fatalf("open tasks = %v", ts)
	}
	if got := tasks(admin2, "open"); len(got) != 1 {
		t.Errorf("a second tenant admin sees %v", got)
	}
	// a person without the approver role does not
	viewer := e.as("viewer", []auth.Role{auth.RoleViewer}, nil)
	if got := viewer.call("GET", "/api/groups/inbox/tasks?kind=deletion_held", "", 200)["items"]; got != nil && len(got.([]any)) != 0 {
		t.Errorf("a viewer sees %v", got)
	}
	// the task is not closed by hand: it follows the hold
	e.admin.call("POST", "/api/groups/inbox/tasks/"+ts[0]["id"].(string)+"/close", `{"status":"dismissed"}`, 409)
	admin2.call("POST", "/api/admin/deletion-holds/"+holdID+"/approve", "", 200)
	if got := tasks(e.admin, "open"); len(got) != 0 {
		t.Errorf("the task is still open after the release: %v", got)
	}
	if got := tasks(e.admin, "done"); len(got) != 1 {
		t.Errorf("done tasks = %v", got)
	}
	// a discarded hold dismisses its task
	held = e.admin.call("DELETE", "/api/groups/"+gs[2], "", 202)
	if got := tasks(e.admin, "open"); len(got) != 1 {
		t.Fatalf("second task = %v", got)
	}
	admin2.call("POST", "/api/admin/deletion-holds/"+held["hold_id"].(string)+"/discard", "", 200)
	if got := tasks(e.admin, "dismissed"); len(got) != 1 {
		t.Errorf("dismissed tasks = %v", got)
	}
}

// Loosening is judged on the effective rate and mode (#468): a single admin cannot scale the burst up with
// the window, and saving the displayed default does not end the hold_all of source-driven runs.
func TestDeletionGuardAPI_LooseningUsesTheEffectiveSettings(t *testing.T) {
	e := newPrivEnv(t)
	a2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	pol := func(cat string, count, window int, mode string) string {
		return fmt.Sprintf(`{"type":"deletion_guard.update","payload":{"policies":[{"category":%q,"max_count":%d,"window_minutes":%d,"mode":%q}]}}`, cat, count, window, mode)
	}
	cat := func(name string) map[string]any {
		for _, c := range e.admin.call("GET", "/api/admin/deletion-guard", "", 200)["categories"].([]any) {
			if c.(map[string]any)["category"] == name {
				return c.(map[string]any)
			}
		}
		t.Fatalf("no category %s", name)
		return nil
	}
	// the displayed default saved as it is: no change, still the unset default
	ch := e.admin.call("POST", "/api/admin/change-requests", pol("groups", 25, 60, "hold_excess"), 201)
	if ch["two_person"] != false || cat("groups")["default"] != true {
		t.Errorf("explicit default: two_person %v, default %v", ch["two_person"], cat("groups")["default"])
	}
	// the same rate with a 168 times larger burst needs two admins
	setGuard(e.admin, a2, pol("groups", 25, 60, "hold_all"))
	ch = e.admin.call("POST", "/api/admin/change-requests", pol("groups", 4200, 10080, "hold_all"), 201)
	if ch["two_person"] != true || ch["status"] != "pending_approval" {
		t.Errorf("25/hour to 4200/week: %v", ch)
	}
	if cat("groups")["limit"] != float64(25) {
		t.Errorf("the limit changed before the approval: %v", cat("groups")["limit"])
	}
	// a tighter setting stays a single-admin change
	if ch := e.admin.call("POST", "/api/admin/change-requests", pol("groups", 10, 60, "hold_all"), 201); ch["two_person"] != false {
		t.Errorf("tightening: %v", ch)
	}
	// a category change that is looser in one field and tighter in another still needs two
	if ch := e.admin.call("POST", "/api/admin/change-requests", pol("groups", 5, 60, "hold_excess"), 201); ch["two_person"] != true {
		t.Errorf("mixed change: %v", ch)
	}
}

// swappableFeed is a connector whose next read the test chooses.
type swappableFeed struct {
	connectors.Connector
	res atomic.Pointer[connectors.DiscoveryResult]
}

func (s *swappableFeed) System() string { return "hr" }
func (s *swappableFeed) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	return s.res.Load(), nil
}

func hrFeed(n int, ended ...int) *connectors.DiscoveryResult {
	r := &connectors.DiscoveryResult{}
	for i := 0; i < n; i++ {
		x := fmt.Sprintf("hr-%02d", i)
		st := "active"
		if slices.Contains(ended, i) {
			st = "terminated"
		}
		r.Identities = append(r.Identities, connectors.IdentityRecord{ExternalID: x, Name: "Person " + x, Type: "human", Status: st})
	}
	return r
}

// A sync queued with ?async=true runs in a worker, but the hold it makes still names the admin who queued
// it, so that admin cannot release it (#487). A scheduled run has no human and exempts nobody.
func TestDeletionGuardAPI_QueuedSyncHoldNamesWhoQueuedIt(t *testing.T) {
	f := storetest.TwoTenants(t)
	feed := &swappableFeed{}
	srv := newIsolationServerWith(f, func(c *Config) {
		c.Connectors = func(time.Time) ([]connectors.Connector, error) { return []connectors.Connector{feed}, nil }
	})
	e := &privEnv{t: t, f: f, srv: srv}
	queuer := e.as("queuer", []auth.Role{auth.RoleTenantAdmin, auth.RolePolicyAdmin}, nil)
	other := e.as("other", []auth.Role{auth.RoleTenantAdmin}, nil)

	feed.res.Store(hrFeed(30))
	queuer.call("POST", "/api/connectors/sync", "", 200)
	// the feed is now short, and two people ended: the worker's run holds both
	feed.res.Store(hrFeed(20, 0, 1))
	queuer.call("POST", "/api/connectors/sync?async=true", "", 200)
	drain(t, srv)

	holds := queuer.call("GET", "/api/admin/deletion-holds?status=held", "", 200)["holds"].([]any)
	if len(holds) != 1 {
		t.Fatalf("holds = %v", holds)
	}
	id := holds[0].(map[string]any)["id"].(string)
	one := queuer.call("GET", "/api/admin/deletion-holds/"+id, "", 200)
	cs, _ := one["reason"].(map[string]any)["contributors"].([]any)
	if len(cs) != 1 || cs[0].(map[string]any)["actor"] == "" || cs[0].(map[string]any)["actor"] == nil {
		t.Fatalf("contributors = %v, want the user who queued the run", cs)
	}
	if got := queuer.call("POST", "/api/admin/deletion-holds/"+id+"/approve", "", 403); got["error"] != "same_actor" {
		t.Errorf("the admin who queued the run released its hold: %v", got)
	}
	if got := other.call("POST", "/api/admin/deletion-holds/"+id+"/approve", "", 200); got["status"] != "released" {
		t.Errorf("another admin: %v", got)
	}
}

// A dead scheduled sync that an admin retries makes holds that name the retrier too, so they cannot
// release them (#495). A sync queued by one admin and retried by another names both.
func TestDeletionGuardAPI_RetriedSyncHoldNamesTheRetrier(t *testing.T) {
	f := storetest.TwoTenants(t)
	feed := &swappableFeed{}
	srv := newIsolationServerWith(f, func(c *Config) {
		c.Connectors = func(time.Time) ([]connectors.Connector, error) { return []connectors.Connector{feed}, nil }
	})
	e := &privEnv{t: t, f: f, srv: srv}
	retrier := e.as("retrier", []auth.Role{auth.RoleTenantAdmin, auth.RolePolicyAdmin}, nil)
	other := e.as("other", []auth.Role{auth.RoleTenantAdmin}, nil)

	feed.res.Store(hrFeed(30))
	retrier.call("POST", "/api/connectors/sync", "", 200)
	feed.res.Store(hrFeed(20, 0, 1))
	dead := deadJob(t, f, f.B.ID, "connector_sync") // a scheduled sync: no requested_by
	retrier.call("POST", "/api/queue/jobs/"+dead+"/retry", "", 200)
	var j *store.QueueJob
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) (err error) { j, err = c.QueueJob(dead); return err })
	var pl worker.SyncPayload
	if json.Unmarshal([]byte(j.Payload), &pl) != nil || len(pl.RetriedBy) != 1 || pl.RequestedBy != "" {
		t.Fatalf("payload after the retry = %q", j.Payload)
	}
	drain(t, srv)

	holds := retrier.call("GET", "/api/admin/deletion-holds?status=held", "", 200)["holds"].([]any)
	if len(holds) != 1 {
		t.Fatalf("holds = %v", holds)
	}
	id := holds[0].(map[string]any)["id"].(string)
	cs, _ := retrier.call("GET", "/api/admin/deletion-holds/"+id, "", 200)["reason"].(map[string]any)["contributors"].([]any)
	if len(cs) != 1 || cs[0].(map[string]any)["actor"] != pl.RetriedBy[0] {
		t.Fatalf("contributors = %v, want the retrier", cs)
	}
	if got := retrier.call("POST", "/api/admin/deletion-holds/"+id+"/approve", "", 403); got["error"] != "same_actor" {
		t.Errorf("the admin who retried the run released its hold: %v", got)
	}
	if got := other.call("POST", "/api/admin/deletion-holds/"+id+"/approve", "", 200); got["status"] != "released" {
		t.Errorf("another admin: %v", got)
	}
}

// Whether an override escapes the category's budget is recorded when it is approved (#494): two admins
// approving a looser override mark it, a single-admin tighter one is not marked, and setting it again
// or removing it clears the mark.
func TestDeletionGuardAPI_SourceApprovalRecorded(t *testing.T) {
	e := newPrivEnv(t)
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	conn := store.NewID()
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
		return c.InsertConnection(&store.Connection{ID: conn, Name: "Workday prod", ConnectorType: "workday", System: "workday",
			Role: "account_source", CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	approved := func() bool {
		var ok bool
		if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) (err error) {
			ok, err = c.DeletionSourceApproved("connection", conn, "accounts")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	set := func(rest string) map[string]any {
		return e.admin.call("POST", "/api/admin/change-requests", srcChange(fmt.Sprintf(
			`{"kind":"connection","source_id":%q,"category":"accounts"%s}`, conn, rest)), 201)
	}
	ch := set(`,"mode":"hold_excess","max_count":100000,"window_minutes":60`) // looser than the category
	if ch["two_person"] != true || approved() {
		t.Fatalf("looser override: %v, approved %v before approval", ch, approved())
	}
	admin2.call("POST", "/api/admin/change-requests/"+ch["id"].(string)+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, ch["payload_hash"]), 200)
	if !approved() {
		t.Error("an override two admins approved as looser is not marked")
	}
	if ch = set(`,"mode":"hold_all","max_count":1,"window_minutes":60`); ch["status"] != "applied" || approved() {
		t.Errorf("tighter single-admin override: %v, approved %v", ch["status"], approved())
	}
}
