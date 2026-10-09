package jml_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

func get(o ojson.Object, k string) any { v, _ := o.Get(k); return v }

func steps(p jml.Plan) []jml.Step { s, _ := get(p, "steps").([]jml.Step); return s }

func stepsWith(p jml.Plan, action string) []jml.Step {
	var out []jml.Step
	for _, s := range steps(p) {
		if get(s, "action") == action {
			out = append(out, s)
		}
	}
	return out
}

func impact(p jml.Plan) ojson.Object { o, _ := get(p, "impact").(ojson.Object); return o }

func TestLeaverPlanContents(t *testing.T) {
	st, ids := testkit.Tiny(t)
	plan, err := jml.LeaverPlan(testkit.Conn(st), testkit.Now, ids["alice"], true, testkit.Policies(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		action string
		count  int
		target string // when set, some step of this action has this target
	}{
		{"disable_account", 1, "alice@t.example"},
		{"remove_grant", 1, "okta:eng"},
		{"reassign_owner", 1, "Helper Bot"},    // alice owns helper-bot ...
		{"revoke_delegation", 1, "Helper Bot"}, // ... and is its delegation principal
		{"cancel_jit", 0, ""},
		{"reassign_reports", 0, ""},
	}
	for _, tc := range tests {
		ss := stepsWith(plan, tc.action)
		if len(ss) != tc.count {
			t.Errorf("%s: %d steps, want %d", tc.action, len(ss), tc.count)
			continue
		}
		if tc.target != "" && !slices.ContainsFunc(ss, func(s jml.Step) bool { return get(s, "target") == tc.target }) {
			t.Errorf("%s: no step targets %q: %v", tc.action, tc.target, ss)
		}
	}
	if got := get(impact(plan), "permissions_removed"); got != 2 {
		t.Errorf("permissions_removed = %v, want 2", got)
	}
	owner := stepsWith(plan, "reassign_owner")[0]
	if get(owner, "new_owner_id") != ids["carol"] {
		t.Errorf("new owner = %v, want carol (alice's manager)", get(owner, "new_owner_id"))
	}
}

func TestLeaverPlanForAlreadyTerminatedIdentityFindsLeftovers(t *testing.T) {
	st, ids := testkit.Tiny(t)
	plan, err := jml.LeaverPlan(testkit.Conn(st), testkit.Now, ids["dave"], true, testkit.Policies(t))
	if err != nil {
		t.Fatal(err)
	}
	var disabled, rotated []any
	for _, s := range stepsWith(plan, "disable_account") {
		disabled = append(disabled, get(s, "target"))
	}
	for _, s := range stepsWith(plan, "rotate_secret") {
		rotated = append(rotated, get(s, "target"))
	}
	if !slices.Equal(disabled, []any{"dave"}) { // the forgotten AWS IAM user
		t.Errorf("disabled = %v", disabled)
	}
	if !slices.Equal(rotated, []any{"AKIAETL"}) { // dave had custody of svc-etl's key
		t.Errorf("rotated = %v", rotated)
	}
	if !slices.ContainsFunc(stepsWith(plan, "reassign_owner"), func(s jml.Step) bool { return get(s, "new_owner_id") == ids["carol"] }) {
		t.Error("svc-etl ownership should move to carol")
	}
	if v, _ := get(impact(plan), "violations_resolved").(int); v < 1 {
		t.Errorf("violations_resolved = %v", get(impact(plan), "violations_resolved"))
	}
}

func TestLeaverPlanUnknownIdentity(t *testing.T) {
	st, _ := testkit.Tiny(t)
	_, err := jml.LeaverPlan(testkit.Conn(st), testkit.Now, 99999, true, nil)
	var je *jml.Error
	if !errors.As(err, &je) || je.Msg != "unknown identity" {
		t.Errorf("err = %v", err)
	}
}

func TestLeaverPlanWithoutImpact(t *testing.T) {
	st, ids := testkit.Tiny(t)
	plan, err := jml.LeaverPlan(testkit.Conn(st), testkit.Now, ids["bob"], false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plan.Get("impact"); ok {
		t.Error("impact must be omitted when not requested")
	}
	if n := len(stepsWith(plan, "remove_grant")); n != 2 {
		t.Errorf("bob remove_grant steps = %d, want 2", n)
	}
}

func TestExecuteLeaverEventRemovesAllAccess(t *testing.T) {
	st, ids := testkit.Tiny(t)
	pols := testkit.Policies(t)
	var evID int64
	testkit.Write(t, st, func(c *store.Conn) error {
		var err error
		evID, err = c.Insert(`INSERT INTO hris_events (external_id, type, identity_id, payload, effective_at, status)
			VALUES ('t-1', 'leaver', ?, '{}', ?, 'pending')`, ids["alice"], store.T(testkit.Now))
		return err
	})
	testkit.Write(t, st, func(c *store.Conn) error {
		_, err := jml.ExecuteEvent(c, testkit.Now, evID, "jml-automation", pols)
		return err
	})
	c := testkit.Conn(st)
	alice, err := c.Identity(ids["alice"])
	if err != nil || alice.Status != "terminated" || alice.TerminatedAt == nil {
		t.Fatalf("alice = %+v %v", alice, err)
	}
	accts, _ := c.IdentityAccounts(alice.ID)
	for _, a := range accts {
		if a.Status != "disabled" {
			t.Errorf("account %s still %s", a.Username, a.Status)
		}
	}
	g, err := graph.FromDB(c, testkit.Now)
	if err != nil {
		t.Fatal(err)
	}
	if n := g.EffectivePermissions(alice.ID).Len(); n != 0 {
		t.Errorf("alice keeps %d permissions", n)
	}
	bot, _ := c.Identities("WHERE external_id = 'helper-bot'")
	if bot[0].OwnerID == nil || *bot[0].OwnerID != ids["carol"] {
		t.Errorf("helper-bot owner = %v, want carol", bot[0].OwnerID)
	}
	vs, err := policy.Evaluate(pols, policy.NewContext(g, c, testkit.Now))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.PolicyID == "terminated-access" && *v.IdentityID == alice.ID {
			t.Error("executed leaver still has a terminated-access violation")
		}
	}
	// executing twice is refused
	err = st.Write(t.Context(), func(c *store.Conn) error {
		_, err := jml.ExecuteEvent(c, testkit.Now, evID, "jml-automation", pols)
		return err
	})
	var je *jml.Error
	if !errors.As(err, &je) || je.Msg != "event already executed" {
		t.Errorf("second execute: %v", err)
	}
}

func demoEvent(t *testing.T, st *store.Store, where string) *store.HrisEvent {
	t.Helper()
	evs, err := testkit.Conn(st).HrisEvents(where + " ORDER BY id")
	if err != nil || len(evs) != 1 {
		t.Fatalf("events %q: %d %v", where, len(evs), err)
	}
	return evs[0]
}

func TestDemoMarcusLeaverPlan(t *testing.T) {
	st := testkit.Demo(t)
	ev := demoEvent(t, st, "WHERE type = 'leaver' AND status = 'pending'")
	plan, err := jml.PlanForEvent(testkit.Conn(st), testkit.Now, ev, true, testkit.Policies(t))
	if err != nil {
		t.Fatal(err)
	}
	if name := get(get(plan, "identity").(ojson.Object), "name"); name != "Marcus Bellweather" {
		t.Errorf("identity = %v", name)
	}
	if !slices.ContainsFunc(stepsWith(plan, "reassign_owner"), func(s jml.Step) bool { return get(s, "target") == "SRE On-call Agent" }) {
		t.Error("SRE On-call Agent ownership should be reassigned")
	}
	if v, _ := get(impact(plan), "privileged_removed").(int); v <= 0 {
		t.Errorf("privileged_removed = %v", get(impact(plan), "privileged_removed"))
	}
}

func TestDemoJoinerAndMoverPlans(t *testing.T) {
	st := testkit.Demo(t)
	c := testkit.Conn(st)
	targets := func(p jml.Plan, action string) []any {
		var out []any
		for _, s := range stepsWith(p, action) {
			out = append(out, get(s, "target"))
		}
		return out
	}
	joiner, err := jml.PlanForEvent(c, testkit.Now, demoEvent(t, st, "WHERE type = 'joiner'"), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"okta:data-team", "snowflake:ANALYST"} {
		if !slices.Contains(targets(joiner, "add_grant"), any(want)) {
			t.Errorf("joiner add_grant missing %s: %v", want, targets(joiner, "add_grant"))
		}
	}
	mover, err := jml.PlanForEvent(c, testkit.Now, demoEvent(t, st, "WHERE type = 'mover'"), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(targets(mover, "remove_grant"), any("okta:support")) {
		t.Errorf("mover remove_grant = %v", targets(mover, "remove_grant"))
	}
	if !slices.Contains(targets(mover, "add_grant"), any("okta:sales")) {
		t.Errorf("mover add_grant = %v", targets(mover, "add_grant"))
	}
}

func TestInferTeamAndBirthright(t *testing.T) {
	st := testkit.Demo(t)
	c := testkit.Conn(st)
	alice, _ := c.Identities("WHERE name = 'Alice Okafor'")
	team, err := jml.InferTeam(c, alice[0].ID)
	if err != nil || team == nil {
		t.Fatalf("team = %v %v", team, err)
	}
	if _, ok := jml.Birthright[*team]; !ok {
		t.Errorf("inferred team %q has no birthright", *team)
	}
}
