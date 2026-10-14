package jml_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
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

// read runs fn in a read-only transaction of st's tenant and returns its error.
func read[T any](st *testkit.DB, fn func(*store.TenantTx) (T, error)) (T, error) {
	var out T
	err := st.ReadTenant(context.Background(), st.Tenant, func(c *store.TenantTx) error {
		var err error
		out, err = fn(c)
		return err
	})
	return out, err
}

func leaverPlan(st *testkit.DB, id int64, withImpact bool, pols []*policy.Policy) (jml.Plan, error) {
	return read(st, func(c *store.TenantTx) (jml.Plan, error) { return jml.LeaverPlan(c, testkit.Now, id, withImpact, pols) })
}

func TestLeaverPlanContents(t *testing.T) {
	st, ids := testkit.Tiny(t)
	plan, err := leaverPlan(st, ids["alice"], true, testkit.Policies(t))
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
	plan, err := leaverPlan(st, ids["dave"], true, testkit.Policies(t))
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
	_, err := leaverPlan(st, 99999, true, nil)
	var je *jml.Error
	if !errors.As(err, &je) || je.Msg != "unknown identity" {
		t.Errorf("err = %v", err)
	}
}

func TestLeaverPlanWithoutImpact(t *testing.T) {
	st, ids := testkit.Tiny(t)
	plan, err := leaverPlan(st, ids["bob"], false, nil)
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
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		alice := ids["alice"]
		evID, err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "t-1", Type: "leaver", IdentityID: &alice,
			EffectiveAt: testkit.Now, Status: "pending"})
		return err
	})
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := jml.ExecuteEvent(c, testkit.Now, evID, store.UserRef{Display: "jml-automation"}, pols)
		return err
	})
	testkit.Read(t, st, func(c *store.TenantTx) error {
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
		g, err := graph.Build(c, testkit.Now)
		if err != nil {
			return err
		}
		if n := g.EffectivePermissions(alice.ID).Len(); n != 0 {
			t.Errorf("alice keeps %d permissions", n)
		}
		bot, err := c.IdentityByExternalID("helper-bot")
		if err != nil {
			return err
		}
		if bot.OwnerID == nil || *bot.OwnerID != ids["carol"] {
			t.Errorf("helper-bot owner = %v, want carol", bot.OwnerID)
		}
		vs, err := policy.Evaluate(pols, policy.NewContext(g, c, testkit.Now))
		if err != nil {
			return err
		}
		for _, v := range vs {
			if v.PolicyID == "terminated-access" && *v.IdentityID == alice.ID {
				t.Error("executed leaver still has a terminated-access violation")
			}
		}
		return nil
	})
	// executing twice is refused
	err := st.InTenant(t.Context(), st.Tenant, func(c *store.TenantTx) error {
		_, err := jml.ExecuteEvent(c, testkit.Now, evID, store.UserRef{Display: "jml-automation"}, pols)
		return err
	})
	var je *jml.Error
	if !errors.As(err, &je) || je.Msg != "event already executed" {
		t.Errorf("second execute: %v", err)
	}
}

func demoEvent(t *testing.T, st *testkit.DB, typ, status string) *store.HrisEvent {
	t.Helper()
	var evs []*store.HrisEvent
	for _, ev := range testkit.Get(t, st, func(c *store.TenantTx) ([]*store.HrisEvent, error) { return c.HrisEvents() }) {
		if ev.Type == typ && (status == "" || ev.Status == status) {
			evs = append(evs, ev)
		}
	}
	if len(evs) != 1 {
		t.Fatalf("events %s/%s: %d", typ, status, len(evs))
	}
	return evs[0]
}

func planFor(st *testkit.DB, ev *store.HrisEvent, pols []*policy.Policy) (jml.Plan, error) {
	return read(st, func(c *store.TenantTx) (jml.Plan, error) { return jml.PlanForEvent(c, testkit.Now, ev, true, pols) })
}

func TestDemoMarcusLeaverPlan(t *testing.T) {
	st := testkit.Demo(t)
	ev := demoEvent(t, st, "leaver", "pending")
	plan, err := planFor(st, ev, testkit.Policies(t))
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
	targets := func(p jml.Plan, action string) []any {
		var out []any
		for _, s := range stepsWith(p, action) {
			out = append(out, get(s, "target"))
		}
		return out
	}
	joiner, err := planFor(st, demoEvent(t, st, "joiner", ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"okta:data-team", "snowflake:ANALYST"} {
		if !slices.Contains(targets(joiner, "add_grant"), any(want)) {
			t.Errorf("joiner add_grant missing %s: %v", want, targets(joiner, "add_grant"))
		}
	}
	mover, err := planFor(st, demoEvent(t, st, "mover", ""), nil)
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
	team, err := read(st, func(c *store.TenantTx) (*string, error) {
		idents, err := c.Identities()
		if err != nil {
			return nil, err
		}
		for _, i := range idents {
			if i.Name == "Alice Okafor" {
				return jml.InferTeam(c, i.ID)
			}
		}
		return nil, errors.New("no Alice Okafor")
	})
	if err != nil || team == nil {
		t.Fatalf("team = %v %v", team, err)
	}
	if _, ok := jml.Birthright[*team]; !ok {
		t.Errorf("inferred team %q has no birthright", *team)
	}
}

// A contractor joiner from the HRIS gets a lifecycle row (issue #159): the
// worker type and end date from the payload, the manager as sponsor.
func TestExecuteJoinerRecordsContractorLifecycle(t *testing.T) {
	st, ids := testkit.Tiny(t)
	pols := testkit.Policies(t)
	end := testkit.Now.Add(90 * 24 * time.Hour)
	var evID int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		evID, err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "t-j", Type: "joiner", EffectiveAt: testkit.Now, Status: "pending",
			Payload: ojson.Object{{Key: "name", Value: "Cass Contractor"}, {Key: "email", Value: "cass@example.com"},
				{Key: "department", Value: "Engineering"}, {Key: "team", Value: "backend"}, {Key: "manager_external_id", Value: "carol"},
				{Key: "worker_type", Value: "contractor"}, {Key: "end_date", Value: timeutil.ISO(end)}}})
		return err
	})
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := jml.ExecuteEvent(c, testkit.Now, evID, store.UserRef{Display: "jml-automation"}, pols)
		return err
	})
	testkit.Read(t, st, func(c *store.TenantTx) error {
		ev, err := c.HrisEvent(evID)
		if err != nil || ev.IdentityID == nil {
			t.Fatalf("event = %+v, %v", ev, err)
		}
		l, err := c.LifecycleFor(*ev.IdentityID)
		if err != nil {
			t.Fatalf("lifecycle: %v", err)
		}
		if l.WorkerType != store.WorkerContractor || l.Source != "hris" || l.EndsAt == nil || !l.EndsAt.Equal(end) ||
			l.SponsorID == nil || *l.SponsorID != ids["carol"] {
			t.Errorf("lifecycle = %+v", l)
		}
		return nil
	})
}

// Containment steps (issue #106): a leaver plan carries revoke_sessions and
// revoke_grants for an account on a system with a live connection, and
// ExecuteEvent runs the plan whether or not they succeeded.
func TestLeaverContainmentSteps(t *testing.T) {
	st, ids := testkit.Tiny(t)
	pols := testkit.Policies(t)
	plan, err := read(st, func(c *store.TenantTx) (jml.Plan, error) {
		return jml.LeaverPlan(c, testkit.Now, ids["alice"], false, pols)
	})
	if err != nil || len(stepsWith(plan, "revoke_sessions")) != 0 || len(stepsWith(plan, "revoke_grants")) != 0 {
		t.Fatalf("no connection, yet containment steps: %v %v", err, steps(plan))
	}

	testkit.Write(t, st, func(c *store.TenantTx) error {
		return c.InsertConnection(&store.Connection{ID: store.NewID(), Name: "Okta", ConnectorType: "okta", System: "okta",
			Role: "account_source", CreatedAt: testkit.Now, UpdatedAt: testkit.Now})
	})
	plan, err = read(st, func(c *store.TenantTx) (jml.Plan, error) {
		return jml.LeaverPlan(c, testkit.Now, ids["alice"], false, pols)
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, grants := stepsWith(plan, "revoke_sessions"), stepsWith(plan, "revoke_grants")
	if len(sess) != 1 || len(grants) != 1 || get(sess[0], "system") != "okta" {
		t.Fatalf("steps: %v", steps(plan))
	}
	// containment comes before the grants are removed
	idx := func(s jml.Step) int {
		return slices.IndexFunc(steps(plan), func(x jml.Step) bool { return get(x, "action") == get(s, "action") })
	}
	if idx(sess[0]) > idx(stepsWith(plan, "remove_grant")[0]) {
		t.Error("revoke_sessions is planned after remove_grant")
	}
	if specs := jml.ContainmentSpecs(plan); len(specs) != 2 {
		t.Errorf("specs %+v", specs)
	}

	var evID int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		alice := ids["alice"]
		var err error
		evID, err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "t-c", Type: "leaver", IdentityID: &alice,
			EffectiveAt: testkit.Now, Status: "pending"})
		return err
	})
	// A failed or unrun containment step never blocks the leaver: ExecuteEvent
	// applies the other steps (the failure is a retry task, made by the caller).
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := jml.ExecuteEvent(c, testkit.Now, evID, store.UserRef{Display: "x"}, pols)
		return err
	})
	testkit.Read(t, st, func(c *store.TenantTx) error {
		a, _ := c.Identity(ids["alice"])
		if a.Status != "terminated" {
			t.Errorf("alice is %s", a.Status)
		}
		return nil
	})
}

func stringOf(v any) string { s, _ := v.(string); return s }
