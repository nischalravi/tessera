package roles_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/abac"
	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The fixture is the tiny world (connectors.Tiny) in tenant B: alice
// (Engineering) is in okta:eng, bob (Finance) in the payments groups, carol
// (Engineering) in platform and eng, dave is terminated. Everyone has an
// okta account, which receives role grants for any system (jit.AccountFor).

type world struct {
	t          *testing.T
	f          *storetest.Fixture
	ids        map[string]int64
	alice, pat roles.Actor // alice is a person; pat administers
	now        time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	w := &world{t: t, f: f, ids: f.B.IDs, now: storetest.Now}
	w.tx(func(c *store.TenantTx) error {
		alice := w.ids["alice"]
		// a decider with no linked identity is refused (approver_unlinked, issue #443)
		patID, err := c.InsertIdentity(&store.Identity{TenantID: c.Tenant(), ExternalID: "pat", Name: "Pat", Type: "human", Status: "active", CreatedAt: w.now})
		if err != nil {
			return err
		}
		for _, u := range []struct {
			a     *roles.Actor
			name  string
			ident *int64
		}{{&w.alice, "Alice", &alice}, {&w.pat, "Pat", &patID}} {
			pu := &store.PlatformUser{DisplayName: u.name, IdentityID: u.ident, CreatedAt: w.now}
			if err := c.InsertPlatformUser(pu); err != nil {
				return err
			}
			*u.a = roles.Actor{UserID: pu.ID, Display: u.name, IdentityID: u.ident}
		}
		return nil
	})
	return w
}

func (w *world) tx(fn func(c *store.TenantTx) error) {
	w.t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, fn); err != nil {
		w.t.Fatal(err)
	}
}

func code(err error) string {
	var e *roles.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

func (w *world) g(name string) int64 { return w.ids["group:"+name] }

// edge returns the edge from a person's okta account to a group, or nil.
func (w *world) edge(c *store.TenantTx, person, group string) *store.GrantEdge {
	w.t.Helper()
	e, err := c.EdgeBetween(graph.Key("account", w.ids["acct:okta:"+person]), graph.Key("group", w.g(group)))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		w.t.Fatal(err)
	}
	return e
}

func (w *world) source(person, group string) string {
	var s string
	w.tx(func(c *store.TenantTx) error {
		if e := w.edge(c, person, group); e != nil {
			s = e.Source
		}
		return nil
	})
	return s
}

func (w *world) members(roleID string) map[string]string {
	out := map[string]string{}
	w.tx(func(c *store.TenantTx) error {
		ms, err := c.RoleMembers(roleID)
		if err != nil {
			return err
		}
		for _, m := range ms {
			for k, v := range w.ids {
				if v == m.IdentityID && !hasPrefix(k) {
					out[k] = m.Source
				}
			}
		}
		return nil
	})
	return out
}

func hasPrefix(k string) bool {
	for _, p := range []string{"group:", "acct:", "resource:", "perm:", "res:"} {
		if len(k) >= len(p) && k[:len(p)] == p {
			return true
		}
	}
	return false
}

func steps(p *roles.Plan, action string) []roles.Step {
	var out []roles.Step
	for _, s := range p.Steps {
		if s.Action == action {
			out = append(out, s)
		}
	}
	return out
}

func (w *world) create(s roles.Spec, dry bool) (*roles.Result, error) {
	var res *roles.Result
	var rerr error
	w.tx(func(c *store.TenantTx) error {
		res, rerr = roles.Create(c, s, w.pat, dry, w.now)
		return nil
	})
	return res, rerr
}

func engSpec(w *world) roles.Spec {
	return roles.Spec{Name: "Engineer", Description: "Day-one engineering access", Risk: "medium",
		Birthright:   &roles.Rule{Department: []string{"Engineering"}},
		Entitlements: []int64{w.g("okta:eng"), w.g("okta:platform")}, Note: "first version"}
}

func TestCreate_RuleAssignsAndGrants(t *testing.T) {
	w := newWorld(t)
	// a dry run shows the plan and changes nothing
	res, err := w.create(engSpec(w), true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Plan.DryRun || res.Plan.Members != 2 || res.Plan.Adds != 1 {
		t.Fatalf("dry-run plan = %+v", res.Plan)
	}
	w.tx(func(c *store.TenantTx) error {
		if rs, _ := c.BusinessRoles(); len(rs) != 0 {
			t.Errorf("dry run saved a role")
		}
		return nil
	})
	if s := w.source("alice", "okta:platform"); s != "" {
		t.Fatalf("dry run granted platform (%s)", s)
	}

	res, err = w.create(engSpec(w), false)
	if err != nil {
		t.Fatal(err)
	}
	// alice and carol are in Engineering; dave is terminated; bob is Finance
	if m := w.members(res.Role.ID); len(m) != 2 || m["alice"] != "rule" || m["carol"] != "rule" {
		t.Fatalf("members = %v", m)
	}
	// alice already had eng (connector) and gets platform from the role
	adds := steps(res.Plan, roles.AddGrant)
	if len(adds) != 1 || adds[0].IdentityID != w.ids["alice"] || adds[0].GroupID != w.g("okta:platform") {
		t.Fatalf("adds = %+v", adds)
	}
	if s := w.source("alice", "okta:platform"); s != "role" {
		t.Errorf("alice platform source = %q", s)
	}
	if s := w.source("alice", "okta:eng"); s != "connector" {
		t.Errorf("alice eng source = %q (left alone)", s)
	}
	w.tx(func(c *store.TenantTx) error {
		vs, err := c.RoleVersions(res.Role.ID)
		if err != nil || len(vs) != 1 || vs[0].Version != 1 || vs[0].Note == nil {
			t.Errorf("versions = %v, %v", vs, err)
		}
		evs, err := c.AuditLog(5)
		if err != nil || len(evs) == 0 || evs[0].Action != "role.create" {
			t.Errorf("audit = %v, %v", evs, err)
		}
		return nil
	})
}

func TestUpdate_RemovesOnlyRoleGrants(t *testing.T) {
	w := newWorld(t)
	res, err := w.create(engSpec(w), false)
	if err != nil {
		t.Fatal(err)
	}
	s := engSpec(w)
	s.Entitlements = []int64{w.g("okta:eng")} // drop platform
	var up *roles.Result
	w.tx(func(c *store.TenantTx) error {
		if _, err := roles.Update(c, res.Role.ID, 7, s, w.pat, false, w.now); code(err) != "version_conflict" {
			t.Errorf("stale version = %v", err)
		}
		up, err = roles.Update(c, res.Role.ID, 1, s, w.pat, false, w.now)
		return err
	})
	if up.Role.Version != 2 {
		t.Errorf("version = %d", up.Role.Version)
	}
	// alice's role grant goes; carol's connector grant stays and is reported
	rm := steps(up.Plan, roles.RemoveGrant)
	if len(rm) != 1 || rm[0].IdentityID != w.ids["alice"] {
		t.Fatalf("removes = %+v", rm)
	}
	keep := steps(up.Plan, roles.KeepGrant)
	if len(keep) != 1 || keep[0].IdentityID != w.ids["carol"] {
		t.Fatalf("keeps = %+v", keep)
	}
	if s := w.source("alice", "okta:platform"); s != "" {
		t.Errorf("alice platform still granted (%s)", s)
	}
	if s := w.source("carol", "okta:platform"); s != "connector" {
		t.Errorf("carol platform = %q", s)
	}
	w.tx(func(c *store.TenantTx) error {
		vs, _ := c.RoleVersions(res.Role.ID)
		if len(vs) != 2 || vs[0].Version != 2 {
			t.Errorf("versions = %d", len(vs))
		}
		return nil
	})
}

func TestOverlappingRoles(t *testing.T) {
	w := newWorld(t)
	a, err := w.create(engSpec(w), false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := w.create(roles.Spec{Name: "Platform on-call", Risk: "high", Entitlements: []int64{w.g("okta:platform")}}, false)
	if err != nil {
		t.Fatal(err)
	}
	w.tx(func(c *store.TenantTx) error {
		res, err := roles.Assign(c, b.Role.ID, w.ids["alice"], "on-call rota", w.pat, false, w.now)
		if err != nil {
			return err
		}
		if res.Plan.Adds != 0 { // she already has platform from the Engineer role
			t.Errorf("assign plan = %+v", res.Plan)
		}
		// retiring Engineer keeps platform: on-call still grants it
		ret, err := roles.Retire(c, a.Role.ID, "replaced", w.pat, false, w.now)
		if err != nil {
			return err
		}
		for _, s := range steps(ret.Plan, roles.RemoveGrant) {
			if s.IdentityID == w.ids["alice"] && s.GroupID == w.g("okta:platform") {
				t.Errorf("retire removed a grant another role justifies")
			}
		}
		if len(steps(ret.Plan, roles.KeepGrant)) == 0 {
			t.Errorf("retire plan has no keep step: %+v", ret.Plan)
		}
		return nil
	})
	if s := w.source("alice", "okta:platform"); s != "role" {
		t.Errorf("alice platform = %q", s)
	}
	if m := w.members(a.Role.ID); len(m) != 0 {
		t.Errorf("retired role still has members %v", m)
	}
	// unassigning on-call now removes platform
	w.tx(func(c *store.TenantTx) error {
		if _, err := roles.Unassign(c, b.Role.ID, w.ids["alice"], "", w.pat, false, w.now); code(err) != "reason_required" {
			t.Errorf("unassign without reason = %v", err)
		}
		res, err := roles.Unassign(c, b.Role.ID, w.ids["alice"], "rota ended", w.pat, false, w.now)
		if err != nil {
			return err
		}
		if res.Plan.Removes != 1 {
			t.Errorf("unassign plan = %+v", res.Plan)
		}
		return nil
	})
	if s := w.source("alice", "okta:platform"); s != "" {
		t.Errorf("alice platform after unassign = %q", s)
	}
}

func TestRuleMembersFollowTheRule(t *testing.T) {
	w := newWorld(t)
	res, err := w.create(engSpec(w), false)
	if err != nil {
		t.Fatal(err)
	}
	id := res.Role.ID
	w.tx(func(c *store.TenantTx) error {
		if _, err := roles.Unassign(c, id, w.ids["alice"], "x", w.pat, false, w.now); code(err) != "assigned_by_rule" {
			t.Errorf("unassign a rule member = %v", err)
		}
		// bob moves to Engineering; carol leaves
		eng := "Engineering"
		if err := c.SetIdentityDepartmentTitle(w.ids["bob"], &eng, nil); err != nil {
			return err
		}
		if err := c.TerminateIdentity(w.ids["carol"], w.now); err != nil {
			return err
		}
		dry, err := roles.Reconcile(c, id, w.pat, true, w.now)
		if err != nil {
			return err
		}
		if dry.Plan.Members != 1 || dry.Plan.Leaves != 1 {
			t.Errorf("reconcile plan = %+v", dry.Plan)
		}
		_, err = roles.Reconcile(c, id, w.pat, false, w.now)
		return err
	})
	if m := w.members(id); len(m) != 2 || m["bob"] != "rule" || m["alice"] != "rule" {
		t.Errorf("members = %v", m)
	}
	if s := w.source("bob", "okta:eng"); s != "role" {
		t.Errorf("bob eng = %q", s)
	}
	// carol's grants were from the connector: the leaver process removes them, not the role
	if s := w.source("carol", "okta:platform"); s != "connector" {
		t.Errorf("carol platform = %q", s)
	}
	// nothing left to do
	w.tx(func(c *store.TenantTx) error {
		again, err := roles.Reconcile(c, id, w.pat, true, w.now)
		if err != nil || len(again.Plan.Steps) != 0 {
			t.Errorf("second reconcile = %+v, %v", again, err)
		}
		return nil
	})
}

func TestDrift(t *testing.T) {
	w := newWorld(t)
	res, err := w.create(roles.Spec{Name: "Builder", Risk: "low", Entitlements: []int64{w.g("okta:eng"), w.g("okta:platform")}}, false)
	if err != nil {
		t.Fatal(err)
	}
	id := res.Role.ID
	w.tx(func(c *store.TenantTx) error {
		if _, err := roles.Assign(c, id, w.ids["bob"], "", w.pat, false, w.now); err != nil {
			return err
		}
		// bob's eng grant is removed outside the role (an access review)
		e := w.edge(c, "bob", "okta:eng")
		if e == nil || e.Source != "role" {
			t.Fatalf("bob eng = %+v", e)
		}
		if err := c.DeleteEdge(e.ID, time.Now()); err != nil {
			return err
		}
		d, err := roles.RoleDrift(c, id, w.now)
		if err != nil {
			return err
		}
		if len(d.Missing) != 1 || d.Missing[0].IdentityID != w.ids["bob"] || len(d.Missing[0].Missing) != 1 {
			t.Errorf("missing = %+v", d.Missing)
		}
		// carol holds both without the role, alice one of two; dave (terminated) is not counted
		if len(d.Holders) != 2 || d.Holders[0].IdentityID != w.ids["carol"] || len(d.Holders[0].Held) != 2 ||
			d.Holders[1].IdentityID != w.ids["alice"] {
			t.Errorf("holders = %+v", d.Holders)
		}
		// reconcile restores bob's grant
		rec, err := roles.Reconcile(c, id, w.pat, false, w.now)
		if err != nil || rec.Plan.Adds != 1 {
			t.Errorf("reconcile = %+v, %v", rec, err)
		}
		return nil
	})
}

func TestValidation(t *testing.T) {
	w := newWorld(t)
	if _, err := w.create(engSpec(w), false); err != nil {
		t.Fatal(err)
	}
	cases := map[string]roles.Spec{
		"name_taken":      engSpec(w),
		"invalid_name":    {Name: " ", Risk: "low", Entitlements: []int64{w.g("okta:eng")}},
		"invalid_risk":    {Name: "x", Risk: "extreme", Entitlements: []int64{w.g("okta:eng")}},
		"no_entitlements": {Name: "x", Risk: "low"},
		"group_not_found": {Name: "x", Risk: "low", Entitlements: []int64{999999}},
		"invalid_rule":    {Name: "x", Risk: "low", Entitlements: []int64{w.g("okta:eng")}, Birthright: &roles.Rule{Type: []string{"robot"}}},
		"owner_not_active": {Name: "x", Risk: "low", Entitlements: []int64{w.g("okta:eng")},
			OwnerIdentityID: ptr(w.ids["dave"])},
	}
	for want, s := range cases {
		if _, err := w.create(s, false); code(err) != want {
			t.Errorf("%s: got %v", want, err)
		}
	}
	// another tenant's group looks missing
	if _, err := w.create(roles.Spec{Name: "x", Risk: "low", Entitlements: []int64{w.f.A.IDs["group:okta:eng"]}}, false); code(err) != "group_not_found" {
		t.Errorf("another tenant's group = %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestRoleRequests(t *testing.T) {
	w := newWorld(t)
	res, err := w.create(roles.Spec{Name: "Payments clerk", Risk: "medium", Requestable: true,
		Entitlements: []int64{w.g("okta:payments-clerks")}}, false)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := w.create(roles.Spec{Name: "Locked", Risk: "low", Entitlements: []int64{w.g("okta:eng")}}, false)
	if err != nil {
		t.Fatal(err)
	}
	id, alice := res.Role.ID, w.ids["alice"]
	var reqID string
	w.tx(func(c *store.TenantTx) error {
		if _, err := roles.Request(c, locked.Role.ID, alice, "x", w.alice, false, w.now); code(err) != "not_requestable" {
			t.Errorf("not requestable = %v", err)
		}
		if _, err := roles.Request(c, id, w.ids["bob"], "x", w.alice, false, w.now); code(err) != "for_others_not_allowed" {
			t.Errorf("for others = %v", err)
		}
		if _, err := roles.Request(c, id, alice, " ", w.alice, false, w.now); code(err) != "justification_required" {
			t.Errorf("no justification = %v", err)
		}
		q, err := roles.Request(c, id, alice, "month-end close", w.alice, false, w.now)
		if err != nil {
			return err
		}
		reqID = q.ID
		if _, err := roles.Request(c, id, alice, "again", w.alice, false, w.now); code(err) != "already_requested" {
			t.Errorf("duplicate = %v", err)
		}
		if _, _, err := roles.Approve(c, q.ID, "", w.alice, w.now); code(err) != "self_approval" {
			t.Errorf("self approval = %v", err)
		}
		if _, err := roles.Cancel(c, q.ID, w.pat, w.now); code(err) != "request_not_found" {
			t.Errorf("cancel by another = %v", err)
		}
		if _, err := roles.Deny(c, q.ID, "", w.pat, w.now); code(err) != "reason_required" {
			t.Errorf("deny without reason = %v", err)
		}
		got, ar, err := roles.Approve(c, q.ID, "ok for close", w.pat, w.now)
		if err != nil {
			return err
		}
		if got.Status != store.RequestApproved || ar.Plan.Adds != 1 {
			t.Errorf("approve = %+v %+v", got, ar.Plan)
		}
		if _, err := roles.Request(c, id, alice, "again", w.alice, false, w.now); code(err) != "already_member" {
			t.Errorf("request when member = %v", err)
		}
		return nil
	})
	if m := w.members(id); m["alice"] != "request" {
		t.Errorf("members = %v", m)
	}
	if s := w.source("alice", "okta:payments-clerks"); s != "role" {
		t.Errorf("alice clerks = %q", s)
	}
	// retiring the role denies pending requests and removes the grant
	w.tx(func(c *store.TenantTx) error {
		q, err := roles.Request(c, id, w.ids["carol"], "cover", w.pat, true, w.now)
		if err != nil {
			return err
		}
		if _, err := roles.Retire(c, id, "process moved to the ERP", w.pat, false, w.now); err != nil {
			return err
		}
		got, err := c.RoleRequest(q.ID)
		if err != nil || got.Status != store.RequestDenied {
			t.Errorf("pending request after retire = %+v, %v", got, err)
		}
		if old, _ := c.RoleRequest(reqID); old.Status != store.RequestApproved {
			t.Errorf("approved request changed to %s", old.Status)
		}
		if _, err := roles.Assign(c, id, alice, "", w.pat, false, w.now); code(err) != "role_retired" {
			t.Errorf("assign retired = %v", err)
		}
		return nil
	})
	if s := w.source("alice", "okta:payments-clerks"); s != "" {
		t.Errorf("alice clerks after retire = %q", s)
	}
}

// A birthright rule can name an attribute policy (issue #162): the lists and
// the policy must both hold, a missing attribute fails the policy, and a
// policy change takes effect at the next reconcile.
func TestRulePolicy(t *testing.T) {
	w := newWorld(t)
	var pol *store.AbacPolicy
	by := abac.Actor{UserID: w.pat.UserID, Display: "Pat"}
	cond := func(s string) *abac.Node {
		n, err := abac.Parse([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	w.tx(func(c *store.TenantTx) error {
		var err error
		pol, err = abac.Create(c, abac.Spec{Name: "Engineering humans", Condition: cond(
			`{"all":[{"attr":"identity.department","op":"eq","value":"Engineering"},{"attr":"identity.type","op":"eq","value":"human"}]}`)}, by, w.now)
		return err
	})
	spec := engSpec(w)
	spec.Birthright = &roles.Rule{Policy: pol.ID}
	res, err := w.create(spec, false)
	if err != nil {
		t.Fatal(err)
	}
	id := res.Role.ID
	if m := w.members(id); len(m) != 2 || m["alice"] != "rule" || m["carol"] != "rule" {
		t.Fatalf("members = %v", m)
	}
	// lists and policy together: Engineering AND title lists nobody has
	both := engSpec(w)
	both.Name = "Both"
	both.Birthright = &roles.Rule{Policy: pol.ID, Title: []string{"Chief"}}
	if r, err := w.create(both, true); err != nil || r.Plan.Members != 0 {
		t.Errorf("lists and policy: %+v, %v", r, err)
	}
	// a rule naming a missing or retired policy is refused
	bad := engSpec(w)
	bad.Name = "Bad"
	bad.Birthright = &roles.Rule{Policy: "00000000-0000-4000-8000-00000000dead"}
	if _, err := w.create(bad, false); code(err) != "invalid_rule" {
		t.Errorf("missing policy = %v", err)
	}
	// widening the policy changes nothing until the role is reconciled; then bob joins
	w.tx(func(c *store.TenantTx) error {
		if _, err := abac.Update(c, pol.ID, 1, abac.Spec{Name: pol.Name, Condition: cond(
			`{"any":[{"attr":"identity.department","op":"eq","value":"Engineering"},{"attr":"identity.department","op":"eq","value":"Finance"}]}`)}, by, w.now); err != nil {
			return err
		}
		if _, err := roles.Reconcile(c, id, w.pat, false, w.now); err != nil {
			return err
		}
		// a policy a rule uses cannot be retired
		if _, err := abac.Retire(c, pol.ID, "x", by, w.now); err == nil {
			t.Error("a policy used by a rule was retired")
		}
		return nil
	})
	if m := w.members(id); m["bob"] != "rule" || len(m) != 3 {
		t.Errorf("after widening: %v", m)
	}
	// someone with no department fails the policy rather than passing a negation
	w.tx(func(c *store.TenantTx) error {
		if err := c.SetIdentityDepartmentTitle(w.ids["bob"], nil, nil); err != nil {
			return err
		}
		if _, err := abac.Update(c, pol.ID, 2, abac.Spec{Name: pol.Name, Condition: cond(
			`{"not":{"attr":"identity.department","op":"eq","value":"Legal"}}`)}, by, w.now); err != nil {
			return err
		}
		_, err := roles.Reconcile(c, id, w.pat, false, w.now)
		return err
	})
	if m := w.members(id); m["bob"] != "" || m["alice"] != "rule" {
		t.Errorf("a missing department granted by negation: %v", m)
	}
}

func TestRuleMatch(t *testing.T) {
	dept := "Finance"
	i := &store.Identity{Type: "human", Status: "active", Department: &dept}
	always := &abac.Node{Attr: "identity.type", Op: abac.OpExists}
	attrs := abac.Attrs{"identity.type": "human"}
	for _, c := range []struct {
		name string
		r    *roles.Rule
		cond *abac.Node
		want bool
	}{
		{"lists only", &roles.Rule{Department: []string{"Finance"}}, nil, true},
		{"lists miss", &roles.Rule{Department: []string{"HR"}}, nil, false},
		{"policy true", &roles.Rule{Policy: "p"}, always, true},
		{"policy missing", &roles.Rule{Policy: "p"}, nil, false},
		{"lists and policy", &roles.Rule{Policy: "p", Department: []string{"HR"}}, always, false},
		{"empty rule", &roles.Rule{}, always, false},
	} {
		if got := c.r.Match(i, c.cond, attrs); got != c.want {
			t.Errorf("%s: Match = %v, want %v", c.name, got, c.want)
		}
	}
	if (&roles.Rule{Policy: "p"}).Matches(i) {
		t.Error("Matches granted a policy rule without its condition")
	}
	i.Status = "terminated"
	if (&roles.Rule{Policy: "p"}).Match(i, always, attrs) {
		t.Error("an inactive identity matched")
	}
}

// A change with thousands of steps must still audit: the detail lists a bounded
// sample and commits to every step with steps_total and steps_sha256 (#797).
func TestAudit_LargePlanStaysUnderCap(t *testing.T) {
	w := newWorld(t)
	const people = 2500 // each yields an add_member and a no_account step: 5,000 steps
	dept := "Bulk"
	w.tx(func(c *store.TenantTx) error {
		for i := 0; i < people; i++ {
			if _, err := c.InsertIdentity(&store.Identity{TenantID: c.Tenant(), ExternalID: fmt.Sprintf("bulk-%d", i),
				Name: fmt.Sprintf("Bulk %d", i), Type: "human", Status: "active", Department: &dept, CreatedAt: w.now}); err != nil {
				return err
			}
		}
		return nil
	})
	check := func(action string, res *roles.Result, min int) {
		t.Helper()
		if len(res.Plan.Steps) < min {
			t.Fatalf("%s: only %d steps", action, len(res.Plan.Steps))
		}
		w.tx(func(c *store.TenantTx) error {
			evs, err := c.AuditEvents(store.AuditFilter{Action: action, Limit: 1})
			if err != nil || len(evs) != 1 {
				t.Fatalf("%s events = %d, %v", action, len(evs), err)
			}
			if n := len(evs[0].Detail); n > canon.MaxDetailBytes {
				t.Errorf("%s detail is %d bytes", action, n)
			}
			var d struct {
				Steps      []json.RawMessage `json:"steps"`
				StepsTotal int               `json:"steps_total"`
				SHA        string            `json:"steps_sha256"`
			}
			if err := json.Unmarshal(evs[0].Detail, &d); err != nil {
				t.Fatal(err)
			}
			want, err := roles.StepsDigest(res.Plan.Steps)
			if err != nil {
				t.Fatal(err)
			}
			if d.StepsTotal != len(res.Plan.Steps) || d.SHA != want || len(d.Steps) != roles.MaxAuditSteps {
				t.Errorf("%s: total=%d sample=%d sha=%s want %d / %s", action, d.StepsTotal, len(d.Steps), d.SHA, len(res.Plan.Steps), want)
			}
			return nil
		})
	}
	s := roles.Spec{Name: "Bulk", Description: "d", Risk: "low", Birthright: &roles.Rule{Department: []string{"Bulk"}}, Entitlements: []int64{w.g("okta:eng")}}
	res, err := w.create(s, false)
	if err != nil {
		t.Fatal(err)
	}
	check("role.create", res, 5000)
	s.Description = "changed"
	s.Entitlements = []int64{w.g("okta:platform")}
	var up *roles.Result
	w.tx(func(c *store.TenantTx) error {
		up, err = roles.Update(c, res.Role.ID, 1, s, w.pat, false, w.now)
		return err
	})
	check("role.update", up, 2500)

	// a small plan is unchanged: every step, no digest
	if d, err := roles.PlanDetailForTest(&roles.Plan{Steps: []roles.Step{{Action: roles.AddMember, IdentityID: 1}}}); err != nil {
		t.Fatal(err)
	} else if _, ok := d.Get("steps_sha256"); ok {
		t.Error("small plan carries a digest")
	}
}
