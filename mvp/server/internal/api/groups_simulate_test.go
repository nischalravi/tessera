package api

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Simulation (issue #48, GR-5): POST /api/groups:simulate answers what changes
// would do to memberships, and writes nothing.

// groupsState is everything the groups tables hold, in a form that compares.
type groupsState struct {
	Groups, Direct, Effective, Deps, Closure, Levels, Factors []string
	Pit                                                       []string
	EventHead                                                 store.GrpEventHead
	NextSeq                                                   int64
	Queue, Idempotency                                        int
	DomainAudit, HTTPAudit                                    int
}

// ptrText prints what a pointer points to ("" for nil), so states compare by value.
func ptrText[T any](p *T) string {
	if p == nil {
		return ""
	}
	return fmt.Sprint(*p)
}

func snapshot(t *testing.T, f *storetest.Fixture) groupsState {
	t.Helper()
	var s groupsState
	// InTenant, not ReadTenant: the engine state row is created on first read
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		list := store.MembersListID(c.Tenant())
		gs, err := c.GrpGroupsAll()
		if err != nil {
			return err
		}
		for _, g := range gs {
			s.Groups = append(s.Groups, fmt.Sprintf("%s|%s|%s|%d|%d|%s|%d", g.ID, g.Name, g.Status, g.EffectiveCount, g.EffectiveVersion, g.RecomputeState, g.Version))
			d, err := c.GrpDirect(store.GrpDirectFilter{Group: g.ID, Limit: 500})
			if err != nil {
				return err
			}
			for _, m := range d {
				s.Direct = append(s.Direct, fmt.Sprintf("%s|%s|%s|%s|%s|%s", m.ID, m.GroupID, m.MemberType, ptrText(m.MemberIdentity), ptrText(m.MemberGroup),
					ptrText(m.DisabledAt)))
			}
			eff, err := c.GrpEffectiveList(g.ID, list, 500, 0)
			if err != nil {
				return err
			}
			for _, r := range eff {
				s.Effective = append(s.Effective, fmt.Sprintf("%s|%d|%d|%s", g.ID, r.Identity, r.Support, r.Since))
			}
			pe, err := c.GrpPitEffectives(string(g.ID))
			if err != nil {
				return err
			}
			for _, p := range pe {
				s.Pit = append(s.Pit, fmt.Sprintf("e|%s|%d|%s|%s|%d", p.Group, p.Identity, p.StartAt, ptrText(p.EndAt), p.StartSeq))
			}
			pd, err := c.GrpPitDirects(string(g.ID))
			if err != nil {
				return err
			}
			for _, p := range pd {
				s.Pit = append(s.Pit, fmt.Sprintf("d|%s|%s|%s|%d", p.Group, p.MemberKey, ptrText(p.EndAt), p.StartSeq))
			}
			po, err := c.GrpPitObjects(string(g.ID))
			if err != nil {
				return err
			}
			for _, p := range po {
				s.Pit = append(s.Pit, fmt.Sprintf("o|%s|%s|%s|%d", p.ObjectID, p.Snapshot, ptrText(p.EndAt), p.StartSeq))
			}
		}
		deps, err := c.GrpDepsAll()
		if err != nil {
			return err
		}
		for _, d := range deps {
			s.Deps = append(s.Deps, fmt.Sprintf("%s|%s|%s", d.Parent, d.Child, d.Kind))
		}
		cl, err := c.GrpClosureAll()
		if err != nil {
			return err
		}
		for _, r := range cl {
			s.Closure = append(s.Closure, fmt.Sprintf("%s|%s|%d|%d", r.Ancestor, r.Descendant, r.Paths, r.MinDepth))
		}
		lv, err := c.GrpLevels()
		if err != nil {
			return err
		}
		for _, l := range lv {
			s.Levels = append(s.Levels, fmt.Sprintf("%s|%d", l.Group, l.Level))
		}
		fs, err := c.GrpFactorsAll()
		if err != nil {
			return err
		}
		for _, d := range fs {
			s.Factors = append(s.Factors, fmt.Sprintf("%s|%s", d.Parent, d.Child))
		}
		if s.EventHead, err = c.GrpEventHead(); err != nil {
			return err
		}
		st, err := c.GrpEngineState()
		if err != nil {
			return err
		}
		s.NextSeq = st.NextSeq
		if s.Queue, err = c.GrpQueueLen(); err != nil {
			return err
		}
		s.Idempotency, err = c.GrpIdempotencyCount()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ledger(t, f.DB, f.B.ID) {
		if e.Action == store.ActionHTTPRequest {
			s.HTTPAudit++
		} else {
			s.DomainAudit++
		}
	}
	return s
}

func simGroup(t *testing.T, got map[string]any, name string) map[string]any {
	t.Helper()
	for _, g := range got["groups"].([]any) {
		if m := g.(map[string]any); m["name"] == name {
			return m
		}
	}
	t.Fatalf("no group %s in %v", name, got["groups"])
	return nil
}

func TestSimulate_NoSideEffects(t *testing.T) {
	c, f := newGrp(t)
	alice, bob := f.B.IDs["alice"], f.B.IDs["bob"]
	app := c.folder("", "app")
	team, staff, other, comp, solo := c.group(app, "team"), c.group(app, "staff"), c.group(app, "other"), c.group(app, "comp"), c.group(app, "solo")
	c.member(team, alice)
	c.member(solo, alice)
	c.call("POST", "/api/groups/"+staff+"/members", `{"group":"`+team+`"}`, 201)
	c.call("POST", "/api/groups/"+comp+"/convert-to-composite", `{"op":"union","factors":["`+staff+`","`+other+`"]}`, 200)

	sim := func(changes string, want int) map[string]any {
		got, _ := c.post("POST", "/api/groups:simulate", `{"changes":[`+changes+`]}`, want)
		return got
	}
	add := func(group string, id int64) string {
		return fmt.Sprintf(`{"kind":"add_member","group":%q,"identity":%d}`, group, id)
	}
	cases := []struct {
		name, changes string
		check         func(t *testing.T, got map[string]any)
	}{
		{"an add shows in the group and everything above it", add(team, bob), func(t *testing.T, got map[string]any) {
			if got["simulated"] != true || got["added"] != float64(3) || got["removed"] != float64(0) || got["truncated"] != false {
				t.Fatalf("simulation = %v", got)
			}
			tm := simGroup(t, got, "app:team")
			if tm["targeted"] != true || tm["before"] != float64(1) || tm["after"] != float64(2) || tm["added"] != float64(1) {
				t.Errorf("team = %v", tm)
			}
			if s := tm["added_sample"].([]any); len(s) != 1 || s[0].(map[string]any)["identity_id"] != float64(bob) || s[0].(map[string]any)["name"] != "Bob" {
				t.Errorf("sample = %v", s)
			}
			for _, name := range []string{"app:staff", "app:comp"} {
				if g := simGroup(t, got, name); g["targeted"] != false || g["added"] != float64(1) || g["after"] != g["before"].(float64)+1 {
					t.Errorf("%s = %v", name, g)
				}
			}
			if ch := got["changes"].([]any)[0].(map[string]any); ch["status"] != "created" || ch["name"] != "app:team" {
				t.Errorf("change = %v", ch)
			}
		}},
		{"removing a nested group takes its members with it", fmt.Sprintf(`{"kind":"remove_member","group":%q,"member":%q}`, staff, team),
			func(t *testing.T, got map[string]any) {
				if got["removed"] != float64(2) || got["added"] != float64(0) {
					t.Errorf("simulation = %v", got)
				}
				if g := simGroup(t, got, "app:staff"); g["removed"] != float64(1) || g["after"] != float64(0) || g["before"] != float64(1) {
					t.Errorf("staff = %v", g)
				}
			}},
		{"an add and its removal net to nothing", add(team, bob) + "," + fmt.Sprintf(`{"kind":"remove_member","group":%q,"member":"%d"}`, team, bob),
			func(t *testing.T, got map[string]any) {
				if got["added"] != float64(0) || got["removed"] != float64(0) || len(got["groups"].([]any)) != 1 {
					t.Errorf("simulation = %v", got)
				}
			}},
		{"a composite's new definition", fmt.Sprintf(`{"kind":"set_composite","group":%q,"op":"intersection","factors":[%q,%q]}`, comp, staff, other),
			func(t *testing.T, got map[string]any) {
				if g := simGroup(t, got, "app:comp"); g["removed"] != float64(1) || g["after"] != float64(0) {
					t.Errorf("comp = %v", g)
				}
			}},
		{"converting a group to a composite discards its direct members", fmt.Sprintf(`{"kind":"convert_to_composite","group":%q,"op":"intersection","factors":[%q,%q],"discard_members":true}`, solo, team, other),
			func(t *testing.T, got map[string]any) {
				if g := simGroup(t, got, "app:solo"); got["removed"] != float64(1) || g["removed"] != float64(1) || g["after"] != float64(0) {
					t.Errorf("simulation = %v", got)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := snapshot(t, f)
			got := sim(tc.changes, 200)
			tc.check(t, got)
			after := snapshot(t, f)
			// the request is audited by its http.request event, and nothing else is written
			if after.HTTPAudit != before.HTTPAudit+1 {
				t.Errorf("http.request events: %d before, %d after, want one more", before.HTTPAudit, after.HTTPAudit)
			}
			after.HTTPAudit = before.HTTPAudit
			if !reflect.DeepEqual(before, after) {
				t.Errorf("a simulation changed state:\nbefore %+v\nafter  %+v", before, after)
			}
		})
	}
	// the real state is what it was
	if m := c.call("GET", "/api/groups/"+team+"/members?filter=effective", "", 200); m["total"] != float64(1) {
		t.Errorf("team after the simulations = %v", m)
	}
	if g := c.call("GET", "/api/groups/"+comp, "", 200); g["effective_count"] != float64(1) {
		t.Errorf("comp after the simulations = %v", g)
	}

	// refusals report the change and leave nothing behind
	before := snapshot(t, f)
	for name, tc := range map[string]struct {
		changes string
		status  int
		code    string
	}{
		"a cycle":          {fmt.Sprintf(`{"kind":"add_member","group":%q,"member_group":%q}`, team, staff), 409, "cycle"},
		"after a good one": {add(team, bob) + "," + fmt.Sprintf(`{"kind":"add_member","group":%q,"member_group":%q}`, team, comp), 409, "cycle"},
		"unknown group":    {add("00000000-0000-4000-8000-00000000d00d", alice), 404, "not_found"},
		"unknown member":   {add(team, 99999999), 422, "unknown_identity"},
		"a composite":      {add(comp, alice), 409, "composite_no_members"},
		"bad kind":         {`{"kind":"explode","group":"` + team + `"}`, 422, "invalid_change"},
		"bad group":        {`{"kind":"add_member","group":"x","identity":1}`, 422, "invalid_group"},
		"both members":     {fmt.Sprintf(`{"kind":"add_member","group":%q,"identity":%d,"member_group":%q}`, team, alice, staff), 422, "invalid_member"},
		"bad factors":      {fmt.Sprintf(`{"kind":"set_composite","group":%q,"op":"union","factors":["x"]}`, comp), 422, "invalid_factors"},
		"one factor":       {fmt.Sprintf(`{"kind":"set_composite","group":%q,"op":"union","factors":[%q]}`, comp, staff), 422, "invalid_composite"},
	} {
		rec := c.do("POST", "/api/groups:simulate", `{"changes":[`+tc.changes+`]}`)
		got := decodeObj(t, rec)
		if rec.Code != tc.status || got["error"] != tc.code {
			t.Errorf("%s: %d %v, want %d %s", name, rec.Code, got, tc.status, tc.code)
		}
		if name != "bad kind" && name != "bad group" && name != "both members" && name != "bad factors" && got["index"] == nil {
			t.Errorf("%s: no index in %v", name, got)
		}
	}
	if n := c.do("POST", "/api/groups:simulate", `{"changes":[]}`); n.Code != 422 {
		t.Errorf("no changes = %d", n.Code)
	}
	after := snapshot(t, f)
	before.HTTPAudit, after.HTTPAudit = 0, 0
	if !reflect.DeepEqual(before, after) {
		t.Errorf("refused simulations changed state:\nbefore %+v\nafter  %+v", before, after)
	}
}

// A simulation is not bound by the synchronous budget, and still queues nothing:
// the same change made for real is queued (202), simulated it is answered in full.
func TestSimulate_IgnoresTheSyncBudgetAndQueuesNothing(t *testing.T) {
	c, f, _ := newGrpEngine(t, 1)
	alice, bob := f.B.IDs["alice"], f.B.IDs["bob"]
	app := c.folder("", "app")
	team, staff := c.group(app, "team"), c.group(app, "staff")
	c.call("POST", "/api/groups/"+staff+"/members", `{"group":"`+team+`"}`, 201)
	before := snapshot(t, f)
	got, _ := c.post("POST", "/api/groups:simulate", fmt.Sprintf(`{"changes":[{"kind":"add_member","group":%q,"identity":%d},{"kind":"add_member","group":%q,"identity":%d}]}`,
		team, alice, team, bob), 200)
	if got["added"] != float64(4) { // two identities into team and staff
		t.Errorf("simulation = %v", got)
	}
	after := snapshot(t, f)
	if after.Queue != 0 || before.Queue != 0 {
		t.Errorf("queue: %d before, %d after", before.Queue, after.Queue)
	}
	before.HTTPAudit, after.HTTPAudit = 0, 0
	if !reflect.DeepEqual(before, after) {
		t.Errorf("simulation changed state:\nbefore %+v\nafter  %+v", before, after)
	}
	// for real, the same change is queued
	c.call("POST", "/api/groups/"+team+"/members", fmt.Sprintf(`{"identity":%d}`, alice), 202)
}

// A simulation is a read of the answer: it asks the privileges of the changes.
func TestSimulate_AsksTheChangesPrivileges(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g, comp, f1 := e.admin.group(app, "g"), e.admin.group(app, "comp"), e.admin.group(app, "f1")
	bob := e.user("bob", "bob")
	add := fmt.Sprintf(`{"changes":[{"kind":"add_member","group":%q,"identity":%d}]}`, g, e.ident("carol"))
	rm := fmt.Sprintf(`{"changes":[{"kind":"remove_member","group":%q,"member":"%d"}]}`, g, e.ident("carol"))
	set := fmt.Sprintf(`{"changes":[{"kind":"convert_to_composite","group":%q,"op":"union","factors":[%q,%q]}]}`, comp, g, f1)
	denied(t, bob, "POST", "/api/groups:simulate", add, "update")
	denied(t, bob, "POST", "/api/groups:simulate", rm, "update")
	denied(t, bob, "POST", "/api/groups:simulate", set, "admin")
	e.grant("/api/groups/"+g, "update", "bob", "")
	bob.call("POST", "/api/groups:simulate", add, 200)
	denied(t, bob, "POST", "/api/groups:simulate", set, "admin")
	e.grant("/api/groups/"+comp, "admin", "bob", "")
	denied(t, bob, "POST", "/api/groups:simulate", set, "read") // and read on the factors
	e.grant("/api/groups/"+g, "read", "bob", "")
	e.grant("/api/groups/"+f1, "read", "bob", "")
	bob.call("POST", "/api/groups:simulate", set, 200)
	// a refusal names the change that was refused (the second of two)
	two := fmt.Sprintf(`{"changes":[{"kind":"add_member","group":%q,"identity":%d},{"kind":"add_member","group":%q,"identity":%d}]}`,
		g, e.ident("carol"), f1, e.ident("carol"))
	if got := decodeObj(t, bob.do("POST", "/api/groups:simulate", two)); got["index"] != float64(1) || got["error"] != "privilege_required" {
		t.Errorf("refusal = %v", got)
	}
}
