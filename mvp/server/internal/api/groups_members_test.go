package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Native groups, memberships and composites (issue #45, GR-2).

func (c grpClient) member(group string, identity int64) {
	c.t.Helper()
	c.call("POST", "/api/groups/"+group+"/members", fmt.Sprintf(`{"identity":%d}`, identity), 201)
}

// newGrpEngine is a one-tenant client whose engine has the given synchronous budget.
func newGrpEngine(t *testing.T, budget int) (grpClient, *storetest.Fixture, *engine.Engine) {
	t.Helper()
	f := storetest.TwoTenants(t)
	eng := engine.New(budget)
	eng.Chunk = 2
	srv := newIsolationServer(f)
	srv.cfg.GroupsEngine = eng
	return grpClient{client{t, asAdmin(t, srv, f.DB, f.B.ID, storetest.Now).Handler()}}, f, eng
}

func storetestClock() func() time.Time { return func() time.Time { return storetest.Now } }

func TestGroupsMembersAPI(t *testing.T) {
	c, f := newGrp(t)
	alice, bob := f.B.IDs["alice"], f.B.IDs["bob"]
	app := c.folder("", "app")
	team, staff := c.group(app, "team"), c.group(app, "staff")

	// add: created, then the same member again updates its dates
	add := c.call("POST", "/api/groups/"+team+"/members", fmt.Sprintf(`{"identity":%d,"reason":"onboarding"}`, alice), 201)
	m := add["member"].(map[string]any)
	if add["effective"] != "applied" || add["op"] != nil || m["type"] != "identity" || m["identity_id"] != float64(alice) ||
		m["active"] != true || m["reason"] != "onboarding" || m["name"] == "" {
		t.Fatalf("add = %v", add)
	}
	later := storetest.Now.Add(48 * time.Hour).Format(time.RFC3339)
	upd := c.call("POST", "/api/groups/"+team+"/members", fmt.Sprintf(`{"identity":%d,"disabled_at":"%s"}`, alice, later), 200)
	if upd["member"].(map[string]any)["disabled_at"] == nil || upd["member"].(map[string]any)["id"] != m["id"] {
		t.Errorf("update = %v", upd)
	}
	c.member(team, bob)
	// effective and direct lists, hasMember
	eff := c.call("GET", "/api/groups/"+team+"/members?filter=effective", "", 200)
	if eff["total"] != float64(2) || eff["stale"] != false || len(eff["items"].([]any)) != 2 {
		t.Errorf("effective = %v", eff)
	}
	dir := c.call("GET", "/api/groups/"+team+"/members?limit=1&offset=1", "", 200)
	if dir["total"] != float64(2) || dir["filter"] != "direct" || len(dir["items"].([]any)) != 1 {
		t.Errorf("direct page = %v", dir)
	}
	if got := c.call("GET", fmt.Sprintf("/api/groups/%s/members/%d", team, alice), "", 200); got["member"] != true {
		t.Errorf("hasMember = %v", got)
	}
	// nesting: team into staff, effective members follow, and so does the group's count
	nest := c.call("POST", "/api/groups/"+staff+"/members", `{"group":"`+team+`"}`, 201)
	if nm := nest["member"].(map[string]any); nm["type"] != "group" || nm["group_id"] != team || nm["name"] != "app:team" {
		t.Errorf("nest = %v", nest)
	}
	if got := c.call("GET", fmt.Sprintf("/api/groups/%s/members/%d", staff, bob), "", 200); got["member"] != true {
		t.Errorf("hasMember through nesting = %v", got)
	}
	if g := c.call("GET", "/api/groups/"+staff, "", 200); g["effective_count"] != float64(2) || g["recompute_state"] != "clean" {
		t.Errorf("staff = %v", g)
	}
	// a cycle is refused with the path, and nothing changes
	cyc := c.call("POST", "/api/groups/"+team+"/members", `{"group":"`+staff+`"}`, 409)
	if cyc["error"] != "cycle" || fmt.Sprint(cyc["path"]) != "[app:staff app:team]" {
		t.Errorf("cycle = %v", cyc)
	}
	c.call("POST", "/api/groups/"+team+"/members", `{"group":"`+team+`"}`, 409)
	// removal: by identity id and by group id
	c.call("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", team, bob), "", 200)
	if got := c.call("GET", fmt.Sprintf("/api/groups/%s/members/%d", staff, bob), "", 200); got["member"] != false {
		t.Errorf("bob still in staff after leaving team: %v", got)
	}
	c.call("DELETE", "/api/groups/"+staff+"/members/"+team, "", 200)
	if got := c.call("GET", fmt.Sprintf("/api/groups/%s/members/%d", staff, alice), "", 200); got["member"] != false {
		t.Errorf("alice still in staff after team left it: %v", got)
	}
	c.call("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", team, bob), "", 404) // not a member any more
	// validation
	for name, tc := range map[string][3]string{
		"both":           {"POST", "/api/groups/" + team + "/members", fmt.Sprintf(`{"identity":%d,"group":"%s"}`, alice, staff)},
		"neither":        {"POST", "/api/groups/" + team + "/members", `{}`},
		"unknown ident":  {"POST", "/api/groups/" + team + "/members", `{"identity":99999999}`},
		"bad group id":   {"POST", "/api/groups/" + team + "/members", `{"group":"nope"}`},
		"bad date":       {"POST", "/api/groups/" + team + "/members", fmt.Sprintf(`{"identity":%d,"disabled_at":"yesterday"}`, alice)},
		"past end":       {"POST", "/api/groups/" + team + "/members", fmt.Sprintf(`{"identity":%d,"disabled_at":"2020-01-01T00:00:00Z"}`, alice)},
		"end before beg": {"POST", "/api/groups/" + team + "/members", fmt.Sprintf(`{"identity":%d,"enabled_from":"%s","disabled_at":"%s"}`, alice, later, storetest.Now.Add(time.Hour).Format(time.RFC3339))},
		"bad filter":     {"GET", "/api/groups/" + team + "/members?filter=x", ""},
		"bad member":     {"DELETE", "/api/groups/" + team + "/members/abc", ""},
		"group member":   {"GET", "/api/groups/" + team + "/members/" + staff, ""},
	} {
		if rec := c.do(tc[0], tc[1], tc[2]); rec.Code != 422 {
			t.Errorf("%s: %s %s = %d %.120s, want 422", name, tc[0], tc[1], rec.Code, rec.Body.String())
		}
	}
	c.call("GET", fmt.Sprintf("/api/groups/%s/members/99999999", team), "", 404)
	c.call("GET", "/api/groups/00000000-0000-4000-8000-000000000000/members", "", 404)
	// a deleted group takes no members; its members are gone from what it feeds
	c.call("DELETE", "/api/groups/"+team, "", 200)
	if rec := c.do("POST", "/api/groups/"+team+"/members", fmt.Sprintf(`{"identity":%d}`, bob)); rec.Code != 409 {
		t.Errorf("add to a deleted group = %d", rec.Code)
	}
}

func TestGroupsCompositeAPI(t *testing.T) {
	c, f := newGrp(t)
	alice, bob, carol := f.B.IDs["alice"], f.B.IDs["bob"], f.B.IDs["carol"]
	app := c.folder("", "app")
	a, b := c.group(app, "a"), c.group(app, "b")
	c.member(a, alice)
	c.member(a, bob)
	c.member(b, bob)
	c.member(b, carol)
	// created as a composite: complement a - b
	comp := c.call("POST", "/api/groups", fmt.Sprintf(`{"folder":"%s","extension":"only_a","definition":"composite","composite_op":"complement","factors":["%s","%s"]}`, app, a, b), 201)
	if comp["definition"] != "composite" || comp["composite_op"] != "complement" || fmt.Sprint(comp["factors"]) != fmt.Sprint([]any{a, b}) {
		t.Fatalf("composite = %v", comp)
	}
	id := comp["id"].(string)
	eff := c.call("GET", "/api/groups/"+id+"/members?filter=effective", "", 200)
	if eff["total"] != float64(1) || eff["items"].([]any)[0].(map[string]any)["identity_id"] != float64(alice) {
		t.Errorf("a minus b = %v", eff)
	}
	// no direct members
	if e := c.call("POST", "/api/groups/"+id+"/members", fmt.Sprintf(`{"identity":%d}`, carol), 409); e["error"] != "composite_no_members" {
		t.Errorf("direct member of a composite = %v", e)
	}
	// redefine: union
	got := c.call("PUT", "/api/groups/"+id+"/composite", fmt.Sprintf(`{"op":"union","factors":["%s","%s"]}`, a, b), 200)
	if got["composite_op"] != "union" || got["effective"] != "applied" {
		t.Errorf("redefined = %v", got)
	}
	if eff := c.call("GET", "/api/groups/"+id+"/members?filter=effective", "", 200); eff["total"] != float64(3) {
		t.Errorf("a union b = %v", eff)
	}
	// a factor that depends on the composite is a cycle
	if e := c.call("PUT", "/api/groups/"+id+"/composite", fmt.Sprintf(`{"op":"union","factors":["%s","%s"]}`, id, b), 409); e["error"] != "cycle" {
		t.Errorf("self factor = %v", e)
	}
	// convert a basic group in place: its direct members block it unless discarded
	conv := fmt.Sprintf(`{"op":"intersection","factors":["%s","%s"]}`, a, b)
	if e := c.call("POST", "/api/groups/"+c.group(app, "c")+"/convert-to-composite", conv, 200); e["definition"] != "composite" {
		t.Errorf("convert of an empty group = %v", e)
	}
	d := c.group(app, "d")
	c.member(d, alice)
	if e := c.call("POST", "/api/groups/"+d+"/convert-to-composite", conv, 409); e["error"] != "has_direct_members" || e["direct_members"] != float64(1) {
		t.Errorf("convert with members = %v", e)
	}
	conv = fmt.Sprintf(`{"op":"intersection","factors":["%s","%s"],"discard_members":true}`, a, b)
	got = c.call("POST", "/api/groups/"+d+"/convert-to-composite", conv, 200)
	if got["definition"] != "composite" || got["effective_count"] != float64(1) { // bob is in both
		t.Errorf("converted = %v", got)
	}
	for name, body := range map[string]string{
		"one factor":  fmt.Sprintf(`{"op":"union","factors":["%s"]}`, a),
		"three comp":  fmt.Sprintf(`{"op":"complement","factors":["%s","%s","%s"]}`, a, b, d),
		"bad op":      fmt.Sprintf(`{"op":"xor","factors":["%s","%s"]}`, a, b),
		"dup":         fmt.Sprintf(`{"op":"union","factors":["%s","%s"]}`, a, a),
		"bad id":      `{"op":"union","factors":["x","y"]}`,
		"unknown":     fmt.Sprintf(`{"op":"union","factors":["%s","00000000-0000-4000-8000-000000000000"]}`, a),
		"not a group": `{"op":"union"}`,
	} {
		if rec := c.do("PUT", "/api/groups/"+id+"/composite", body); rec.Code != 422 {
			t.Errorf("%s: %d %.120s, want 422", name, rec.Code, rec.Body.String())
		}
	}
	c.call("PUT", "/api/groups/"+a+"/composite", fmt.Sprintf(`{"op":"union","factors":["%s","%s"]}`, b, d), 409) // a is basic
	if rec := c.do("POST", "/api/groups", fmt.Sprintf(`{"folder":"%s","extension":"x","definition":"policy"}`, app)); rec.Code != 422 {
		t.Errorf("policy definition = %d", rec.Code)
	}
}

// TestGroupsSyncBudgetAPI: a nesting too big for the budget commits, answers
// 202 with an operation id and leaves the group pending and stale until the
// engine's queue worker has run.
func TestGroupsSyncBudgetAPI(t *testing.T) {
	c, f, eng := newGrpEngine(t, 4)
	ctx := context.Background()
	var idents []int64
	err := f.DB.InTenant(ctx, f.B.ID, func(tx *store.TenantTx) error {
		for i := 0; i < 7; i++ {
			id, err := tx.InsertIdentity(&store.Identity{ExternalID: fmt.Sprint("bulk", i), Name: fmt.Sprint("Bulk ", i), Type: "person",
				Status: "active", CreatedAt: storetest.Now})
			if err != nil {
				return err
			}
			idents = append(idents, id)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	app := c.folder("", "app")
	child, parent := c.group(app, "child"), c.group(app, "parent")
	for _, id := range idents {
		c.member(child, id)
	}
	res := c.call("POST", "/api/groups/"+parent+"/members", `{"group":"`+child+`"}`, 202)
	op, _ := res["op"].(float64)
	if res["effective"] != "pending" || op < 1 {
		t.Fatalf("answer = %v, want pending with an op id", res)
	}
	if g := c.call("GET", "/api/groups/"+parent, "", 200); g["recompute_state"] != "pending" || g["effective_count"] != float64(0) {
		t.Errorf("parent while queued = %v", g)
	}
	if l := c.call("GET", "/api/groups/"+parent+"/members?filter=effective", "", 200); l["stale"] != true {
		t.Errorf("effective listing while queued = %v", l)
	}
	if st := c.call("GET", fmt.Sprintf("/api/groups/engine/ops/%d", int(op)), "", 200); st["state"] != "pending" || st["done"] != float64(0) || st["total"].(float64) < 7 {
		t.Errorf("op = %v", st)
	}
	r := &engine.Runner{DB: f.DB, Engine: eng, Clock: storetestClock()}
	if _, err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if st := c.call("GET", fmt.Sprintf("/api/groups/engine/ops/%d", int(op)), "", 200); st["state"] != "done" {
		t.Errorf("op after the worker ran = %v", st)
	}
	g := c.call("GET", "/api/groups/"+parent, "", 200)
	if g["recompute_state"] != "clean" || g["effective_count"] != float64(7) {
		t.Errorf("parent after the worker = %v", g)
	}
	// the removal is queued the same way
	if res := c.call("DELETE", "/api/groups/"+parent+"/members/"+child, "", 202); res["effective"] != "pending" {
		t.Errorf("remove = %v", res)
	}
	if _, err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if g := c.call("GET", "/api/groups/"+parent, "", 200); g["effective_count"] != float64(0) || g["recompute_state"] != "clean" {
		t.Errorf("parent after the removal = %v", g)
	}
	c.call("GET", "/api/groups/engine/ops/999", "", 404)
	c.call("GET", "/api/groups/engine/ops/zero", "", 404)
	// a verification finds nothing wrong
	if v := c.call("POST", "/api/groups/engine/verify", "", 200); v["repair_count"] != float64(0) || v["groups"] != float64(2) {
		t.Errorf("verify = %v", v)
	}
}

func TestGroupsGroupDatesAPI(t *testing.T) {
	c, f := newGrp(t)
	app := c.folder("", "app")
	g := c.group(app, "g")
	c.member(g, f.B.IDs["alice"])
	end := storetest.Now.Add(time.Hour).Format(time.RFC3339)
	got := c.call("PATCH", "/api/groups/"+g, `{"disabled_at":"`+end+`"}`, 200)
	if got["disabled_at"] == nil || got["effective_count"] != float64(1) {
		t.Errorf("patched = %v", got)
	}
	// enabled_from in the future empties the group now
	got = c.call("PATCH", "/api/groups/"+g, `{"enabled_from":"`+storetest.Now.Add(30*time.Minute).Format(time.RFC3339)+`"}`, 200)
	if got["effective_count"] != float64(0) {
		t.Errorf("group before its enabled_from = %v", got)
	}
	// clearing both brings the member back
	got = c.call("PATCH", "/api/groups/"+g, `{"enabled_from":"","disabled_at":""}`, 200)
	if got["effective_count"] != float64(1) || got["enabled_from"] != nil || got["disabled_at"] != nil {
		t.Errorf("cleared = %v", got)
	}
	for _, body := range []string{`{"disabled_at":"soon"}`, `{"enabled_from":"` + end + `","disabled_at":"` + storetest.Now.Format(time.RFC3339) + `"}`} {
		if rec := c.do("PATCH", "/api/groups/"+g, body); rec.Code != 422 {
			t.Errorf("PATCH %s = %d, want 422", body, rec.Code)
		}
	}
}

// TestGroupsMembersAudited: each change writes its domain event in its
// transaction, naming the acting user; a refused one writes none.
func TestGroupsMembersAudited(t *testing.T) {
	c, f := newGrp(t)
	alice := f.B.IDs["alice"]
	app := c.folder("", "app")
	a, b := c.group(app, "a"), c.group(app, "b")
	c.member(a, alice)
	c.call("POST", "/api/groups/"+a+"/members", fmt.Sprintf(`{"identity":%d,"reason":"again"}`, alice), 200)
	c.call("POST", "/api/groups/"+b+"/members", `{"group":"`+a+`"}`, 201)
	c.call("POST", "/api/groups/"+a+"/members", `{"group":"`+b+`"}`, 409) // refused: no event
	c.call("DELETE", "/api/groups/"+b+"/members/"+a, "", 200)
	conv := c.group(app, "conv")
	c.call("POST", "/api/groups/"+conv+"/convert-to-composite", fmt.Sprintf(`{"op":"union","factors":["%s","%s"]}`, a, b), 200)
	c.call("PUT", "/api/groups/"+conv+"/composite", fmt.Sprintf(`{"op":"intersection","factors":["%s","%s"]}`, a, b), 200)
	count := func(action string) (n int) {
		err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
			evs, err := tx.AuditEvents(store.AuditFilter{Action: action})
			for _, e := range evs {
				n++
				if e.ActorType != store.ActorUser || e.ActorID == nil {
					t.Errorf("%s event actor = %s %v", action, e.ActorType, e.ActorID)
				}
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for action, want := range map[string]int{"groups.member.added": 2, "groups.member.updated": 1, "groups.member.removed": 1,
		"groups.group.converted": 1, "groups.composite.updated": 1} {
		if n := count(action); n != want {
			t.Errorf("%s events = %d, want %d", action, n, want)
		}
	}
}

func TestGroupsMembersTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := grpClient{client{t, isolationServer(t, f, f.A.ID).Handler()}}
	b := grpClient{client{t, isolationServer(t, f, f.B.ID).Handler()}}
	af := a.folder("", "app")
	ag, ag2 := a.group(af, "admins"), a.group(af, "other")
	a.member(ag, f.A.IDs["alice"])
	bf := b.folder("", "app")
	bg := b.group(bf, "mine")
	for _, tc := range [][3]string{
		{"GET", "/api/groups/" + ag + "/members", ""},
		{"GET", "/api/groups/" + ag + "/members?filter=effective", ""},
		{"POST", "/api/groups/" + ag + "/members", fmt.Sprintf(`{"identity":%d}`, f.B.IDs["alice"])},
		{"DELETE", fmt.Sprintf("/api/groups/%s/members/%d", ag, f.A.IDs["alice"]), ""},
		{"GET", fmt.Sprintf("/api/groups/%s/members/%d", ag, f.A.IDs["alice"]), ""},
		{"POST", "/api/groups/" + ag + "/convert-to-composite", fmt.Sprintf(`{"op":"union","factors":["%s","%s"]}`, bg, bg)},
		{"PUT", "/api/groups/" + ag + "/composite", fmt.Sprintf(`{"op":"union","factors":["%s","%s"]}`, bg, bg)},
	} {
		if rec := b.do(tc[0], tc[1], tc[2]); rec.Code != 404 {
			t.Errorf("B %s %s = %d %.100s, want 404", tc[0], tc[1], rec.Code, rec.Body.String())
		}
	}
	// B cannot nest A's group, use A's group as a factor, or add A's identity
	if rec := b.do("POST", "/api/groups/"+bg+"/members", `{"group":"`+ag2+`"}`); rec.Code != 422 {
		t.Errorf("B nests A's group = %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do("POST", "/api/groups/"+bg+"/members", fmt.Sprintf(`{"identity":%d}`, f.A.IDs["bob"])); rec.Code != 201 && rec.Code != 422 {
		t.Errorf("B adds an identity id that is also a row of A: %d", rec.Code)
	}
	if rec := b.do("POST", "/api/groups/"+bg+"/convert-to-composite", fmt.Sprintf(`{"op":"union","factors":["%s","%s"]}`, ag, ag2)); rec.Code != 422 {
		t.Errorf("B uses A's groups as factors = %d %s", rec.Code, rec.Body.String())
	}
	if got := a.call("GET", "/api/groups/"+ag+"/members?filter=effective", "", 200); got["total"] != float64(1) {
		t.Errorf("A's members after B's attempts = %v", got)
	}
	b.call("GET", "/api/groups/engine/ops/1", "", 404) // B has issued no operations
}

func TestGroupsMemberRoutesRequireTenantAdmin(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	id := "00000000-0000-4000-8000-000000000000"
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		for _, tc := range [][3]string{
			{"GET", "/api/groups/" + id + "/members", ""}, {"POST", "/api/groups/" + id + "/members", `{"identity":1}`},
			{"GET", "/api/groups/" + id + "/members/1", ""}, {"DELETE", "/api/groups/" + id + "/members/1", ""},
			{"POST", "/api/groups/" + id + "/convert-to-composite", `{}`}, {"PUT", "/api/groups/" + id + "/composite", `{}`},
			{"POST", "/api/groups/engine/verify", ""}, {"GET", "/api/groups/engine/ops/1", ""},
		} {
			if rec := serve(h, authed(l, tc[0], tc[1], tc[2])); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s = %d, want 403", role, tc[0], tc[1], rec.Code)
			}
		}
	}
}
