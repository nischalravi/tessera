package engine_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func wantCode(t *testing.T, err error, kind model.Kind, code string) *model.Error {
	t.Helper()
	var me *model.Error
	if !errors.As(err, &me) || me.Kind != kind || me.Code != code {
		t.Fatalf("err = %v, want kind %d code %s", err, kind, code)
	}
	return me
}

// TestEngine_ClosureAndLevels: a diamond A > B,C > D keeps support counts, path
// counts and levels right while edges come and go.
func TestEngine_ClosureAndLevels(t *testing.T) {
	x := newHarness(t, 4, 2, nil)
	a, b, c, d := x.groups[0], x.groups[1], x.groups[2], x.groups[3]
	alice := x.idents[0]
	x.addIdentity(d, alice)
	for _, e := range [][2]store.GroupID{{b, d}, {c, d}, {a, b}, {a, c}} {
		if err := x.addGroup(e[0], e[1]); err != nil {
			t.Fatal(err)
		}
	}
	// alice reaches A through two paths, B and C through one
	if got := [4]int32{x.support(a, alice), x.support(b, alice), x.support(c, alice), x.support(d, alice)}; got != [4]int32{2, 1, 1, 1} {
		t.Errorf("support A,B,C,D = %v, want [2 1 1 1]", got)
	}
	x.read(func(e model.Env) error {
		cl, err := e.Tx.GrpClosureGet(a, d)
		if err != nil || cl.Paths != 2 || cl.MinDepth != 2 {
			t.Errorf("closure A>D = %+v, %v; want 2 paths of depth 2", cl, err)
		}
		for g, want := range map[store.GroupID]int{a: 2, b: 1, c: 1, d: 0} {
			if got, err := e.Tx.GrpLevel(g); err != nil || got != want {
				t.Errorf("level of %s = %d, %v; want %d", g, got, err, want)
			}
		}
		return nil
	})
	// dropping one path leaves alice in A with support 1, and the closure counts one path
	x.must(func(e model.Env) error { _, err := e.RemoveMember(b, string(d)); return err })
	if got := x.support(a, alice); got != 1 {
		t.Errorf("support of A after one path went = %d, want 1", got)
	}
	x.read(func(e model.Env) error {
		cl, err := e.Tx.GrpClosureGet(a, d)
		if err != nil || cl.Paths != 1 || cl.MinDepth != 2 {
			t.Errorf("closure A>D = %+v, %v; want 1 path of depth 2", cl, err)
		}
		if _, err := e.Tx.GrpClosureGet(b, d); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("closure B>D after removal = %v, want not found", err)
		}
		if lv, _ := e.Tx.GrpLevel(b); lv != 0 {
			t.Errorf("level of B = %d, want 0 (it no longer has a child)", lv)
		}
		if lv, _ := e.Tx.GrpLevel(a); lv != 2 {
			t.Errorf("level of A = %d, want 2 (A > C > D)", lv)
		}
		return nil
	})
	x.verifyClean()
}

// TestEngine_CycleVeto: an edge whose parent is already a descendant of the
// child is refused with the path, for nesting, a factor and a self edge, and
// the refused change leaves no trace.
func TestEngine_CycleVeto(t *testing.T) {
	x := newHarness(t, 4, 1, nil)
	a, b, c, d := x.groups[0], x.groups[1], x.groups[2], x.groups[3]
	if err := x.addGroup(a, b); err != nil {
		t.Fatal(err)
	}
	if err := x.addGroup(b, c); err != nil {
		t.Fatal(err)
	}
	// C into A would close A > B > C > A
	err := x.addGroup(c, a)
	me := wantCode(t, err, model.Conflict, "cycle")
	if path, _ := me.Extra["path"].([]string); !slices.Equal(path, []string{"g0", "g1", "g2"}) {
		t.Errorf("cycle path = %v, want [g0 g1 g2] (from the child down to the parent)", me.Extra["path"])
	}
	wantCode(t, x.addGroup(a, a), model.Conflict, "cycle")
	// a composite whose factor depends on it
	err = x.run(func(e model.Env) error {
		_, _, err := e.ConvertToComposite(c, model.CompositeInput{Op: store.CompUnion, Factors: []store.GroupID{a, d}, DiscardMembers: true})
		return err
	})
	wantCode(t, err, model.Conflict, "cycle")
	// nothing of the refused changes is stored
	x.read(func(e model.Env) error {
		if rows, err := e.Tx.GrpDirect(store.GrpDirectFilter{Group: c}); err != nil || len(rows) != 0 {
			t.Errorf("C's direct rows after the refusals = %v, %v", rows, err)
		}
		if g, _ := e.Group(c); g.Definition != store.DefinitionBasic {
			t.Errorf("C became %s", g.Definition)
		}
		deps, _ := e.Tx.GrpDepsAll()
		if len(deps) != 2 {
			t.Errorf("deps = %v, want the two accepted edges", deps)
		}
		return nil
	})
	x.verifyClean()
}

// TestEngine_SyncBudgetFallsBackToQueue: a change that fits the budget is done
// in the request; one that does not commits the direct row, queues a recompute
// and marks the group pending, and draining the queue finishes it.
func TestEngine_SyncBudgetFallsBackToQueue(t *testing.T) {
	eng := engine.New(10)
	eng.Chunk = 7
	x := newHarness(t, 3, 30, eng)
	small, big, top := x.groups[0], x.groups[1], x.groups[2]
	for _, id := range x.idents[:5] {
		x.addIdentity(small, id)
	}
	for _, id := range x.idents { // 30 members is over the budget of 10 only when nested
		x.addIdentity(big, id)
	}
	// under budget: 5 members x (0 ancestors + 1) = 5 <= 10, applied at once
	var out model.Outcome
	x.must(func(e model.Env) error {
		r, err := e.AddMember(top, model.MemberInput{Group: small})
		out = r.Outcome
		return err
	})
	if out.Queued || x.support(top, x.idents[0]) != 1 || x.group(top).EffectiveCount != 5 {
		t.Fatalf("small nesting: outcome %+v, count %d; want applied in the request", out, x.group(top).EffectiveCount)
	}
	// over budget: 30 members
	x.must(func(e model.Env) error {
		r, err := e.AddMember(top, model.MemberInput{Group: big})
		out = r.Outcome
		return err
	})
	if !out.Queued || out.Op == 0 {
		t.Fatalf("big nesting outcome = %+v, want queued with an op id", out)
	}
	g := x.group(top)
	if g.RecomputeState != "pending" || g.EffectiveCount != 5 {
		t.Errorf("top while queued: state %s count %d, want pending with the 5 it had", g.RecomputeState, g.EffectiveCount)
	}
	x.read(func(e model.Env) error {
		if rows, err := e.Tx.GrpDirect(store.GrpDirectFilter{Group: top}); err != nil || len(rows) != 2 {
			t.Errorf("the direct rows were not committed with the queue entry: %v, %v", rows, err)
		}
		pr, err := engine.OpProgress(e.Tx, out.Op)
		if err != nil || pr.State != store.OpPending || pr.Done != 0 || pr.Total == 0 {
			t.Errorf("progress = %+v, %v", pr, err)
		}
		return nil
	})
	if chunks := x.drain(); chunks < 4 { // 30 identities in chunks of 7
		t.Errorf("drained in %d chunks, want at least 4", chunks)
	}
	g = x.group(top)
	if g.RecomputeState != "clean" || g.EffectiveCount != 30 {
		t.Errorf("top after the drain: state %s count %d, want clean with 30", g.RecomputeState, g.EffectiveCount)
	}
	x.read(func(e model.Env) error {
		if pr, err := engine.OpProgress(e.Tx, out.Op); err != nil || pr.State != store.OpDone {
			t.Errorf("progress after the drain = %+v, %v", pr, err)
		}
		if pr, err := engine.OpProgress(e.Tx, 9999); err != nil || pr.State != store.OpUnknown {
			t.Errorf("progress of an op never issued = %+v, %v", pr, err)
		}
		return nil
	})
	x.verifyClean()
}

// TestEngine_QueuedJobSurvivesInterleavedChange: a direct change made while a
// recompute waits in the queue is not lost or double counted.
func TestEngine_QueuedJobSurvivesInterleavedChange(t *testing.T) {
	eng := engine.New(3)
	eng.Chunk = 2
	x := newHarness(t, 2, 12, eng)
	child, parent := x.groups[0], x.groups[1]
	for _, id := range x.idents[:8] {
		x.addIdentity(child, id)
	}
	if err := x.addGroup(parent, child); err != nil {
		t.Fatal(err)
	}
	if x.group(parent).RecomputeState != "pending" {
		t.Fatal("the nesting should have been queued")
	}
	// one chunk runs, then people come and go in the child
	x.must(func(e model.Env) error { _, err := x.eng.Drain(e.Tx, x.now); return err })
	x.must(func(e model.Env) error {
		_, err := e.RemoveMember(child, strconv.FormatInt(x.idents[0], 10))
		return err
	})
	x.addIdentity(child, x.idents[9])
	x.drain()
	for _, id := range x.idents {
		in := slices.Contains(append([]int64{}, x.idents[1:8]...), id) || id == x.idents[9]
		if got := x.support(parent, id) > 0; got != in {
			t.Errorf("identity %d in parent = %v, want %v", id, got, in)
		}
	}
	x.verifyClean()
}

// TestTimewheel_DisableWithin60s: with the Runner ticking every 30 simulated
// seconds, a membership whose disabled_at passes is gone from the effective
// set, and from every group it feeds, within 60 seconds. A precise wake-up is
// reported too.
func TestTimewheel_DisableWithin60s(t *testing.T) {
	x := newHarness(t, 3, 2, nil)
	leaf, mid, top := x.groups[0], x.groups[1], x.groups[2]
	alice := x.idents[0]
	disable := t0.Add(47 * time.Second)
	x.must(func(e model.Env) error {
		_, err := e.AddMember(leaf, model.MemberInput{Identity: &alice, DisabledAt: &disable})
		return err
	})
	if err := x.addGroup(mid, leaf); err != nil {
		t.Fatal(err)
	}
	if err := x.addGroup(top, mid); err != nil {
		t.Fatal(err)
	}
	if x.support(top, alice) != 1 {
		t.Fatal("alice should be in top before her date")
	}
	var clock = t0
	r := &engine.Runner{DB: x.db, Engine: x.eng, Clock: func() time.Time { return clock }}
	var wake *time.Time
	gone := time.Time{}
	for s := 0; s <= 150 && gone.IsZero(); s++ {
		clock = t0.Add(time.Duration(s) * time.Second)
		var err error
		if wake, err = r.Once(context.Background()); err != nil {
			t.Fatal(err)
		}
		if s == 0 && (wake == nil || !wake.Equal(disable)) {
			t.Errorf("next boundary at start = %v, want %v", wake, disable)
		}
		x.now = clock
		if x.support(top, alice) == 0 {
			gone = clock
		}
	}
	if gone.IsZero() {
		t.Fatal("alice never left top")
	}
	if lag := gone.Sub(disable); lag < 0 || lag > 60*time.Second {
		t.Errorf("the membership ended %s after its date, want within 60s", lag)
	}
	for _, g := range x.groups {
		if x.support(g, alice) != 0 {
			t.Errorf("alice still in %s", g)
		}
	}
	x.verifyClean()
}

// TestTimewheel_EnableAndGroupDates: an enabled_from starts counting at its
// time, and a group's own disabled_at empties it (and becomes a status change).
func TestTimewheel_EnableAndGroupDates(t *testing.T) {
	x := newHarness(t, 2, 1, nil)
	leaf, top := x.groups[0], x.groups[1]
	alice := x.idents[0]
	from, end := t0.Add(40*time.Second), t0.Add(100*time.Second)
	x.must(func(e model.Env) error {
		_, err := e.AddMember(leaf, model.MemberInput{Identity: &alice, EnabledFrom: &from})
		return err
	})
	if err := x.addGroup(top, leaf); err != nil {
		t.Fatal(err)
	}
	if x.support(top, alice) != 0 {
		t.Fatal("not yet enabled")
	}
	x.advance(45 * time.Second)
	if x.support(leaf, alice) != 1 || x.support(top, alice) != 1 {
		t.Fatal("enabled_from passed: alice should be in leaf and top")
	}
	x.must(func(e model.Env) error {
		_, err := e.UpdateGroup(leaf, model.UpdateGroupInput{DisabledAt: &end})
		return err
	})
	if x.support(leaf, alice) != 1 {
		t.Fatal("the group is still inside its dates")
	}
	x.advance(60 * time.Second)
	if x.support(leaf, alice) != 0 || x.support(top, alice) != 0 {
		t.Error("the group's disabled_at passed: it and its parent should be empty")
	}
	if g := x.group(leaf); g.Status != store.GroupDisabled {
		t.Errorf("status after the date = %s, want disabled", g.Status)
	}
	x.verifyClean()
}

// TestIsMember_IgnoresExpiredRowsWhenWheelLags: with the clock past a row's
// disabled_at and no tick yet, the materialized row is still there but IsMember
// does not count it, for an identity row, a nested group row and a composite.
func TestIsMember_IgnoresExpiredRowsWhenWheelLags(t *testing.T) {
	x := newHarness(t, 4, 1, nil)
	leaf, nest, other, comp := x.groups[0], x.groups[1], x.groups[2], x.groups[3]
	alice := x.idents[0]
	soon := t0.Add(10 * time.Second)
	x.must(func(e model.Env) error {
		_, err := e.AddMember(leaf, model.MemberInput{Identity: &alice, DisabledAt: &soon})
		return err
	})
	x.addIdentity(other, alice)
	if err := x.addGroup(nest, leaf); err != nil {
		t.Fatal(err)
	}
	x.must(func(e model.Env) error {
		_, _, err := e.ConvertToComposite(comp, model.CompositeInput{Op: store.CompIntersection, Factors: []store.GroupID{leaf, other}})
		return err
	})
	for _, g := range []store.GroupID{leaf, nest, comp} {
		if !x.isMember(g, alice) {
			t.Fatalf("alice should be in %s before her date", g)
		}
	}
	x.now = t0.Add(20 * time.Second) // the wheel has not ticked
	for _, g := range []store.GroupID{leaf, nest, comp} {
		if x.support(g, alice) == 0 {
			t.Fatalf("the materialized row of %s vanished without a tick: the test needs the wheel to lag", g)
		}
		if x.isMember(g, alice) {
			t.Errorf("IsMember(%s) counted a membership whose disabled_at passed", g)
		}
	}
	if !x.isMember(other, alice) {
		t.Error("an unrelated membership stopped counting")
	}
	x.tick()
	for _, g := range []store.GroupID{leaf, nest, comp} {
		if x.support(g, alice) != 0 {
			t.Errorf("after the tick alice is still in %s", g)
		}
	}
}

// snapshot is everything the engine derives.
type snapshot struct {
	Effective map[store.GroupID][]store.GrpEffectiveRow
	Counts    map[store.GroupID]int64
	Closure   []store.GrpClosureRow
	Levels    []store.GrpLevel
	Deps      []store.GrpDep
}

func (x *harness) snapshot() snapshot {
	x.t.Helper()
	s := snapshot{Effective: map[store.GroupID][]store.GrpEffectiveRow{}, Counts: map[store.GroupID]int64{}}
	x.read(func(e model.Env) error {
		var err error
		for _, g := range x.groups {
			if s.Effective[g], err = e.Tx.GrpEffectiveList(g, x.list(), 1000, 0); err != nil {
				return err
			}
			gr, err := e.Group(g)
			if err != nil {
				return err
			}
			s.Counts[g] = gr.EffectiveCount
		}
		if s.Closure, err = e.Tx.GrpClosureAll(); err != nil {
			return err
		}
		if s.Levels, err = e.Tx.GrpLevels(); err != nil {
			return err
		}
		s.Deps, err = e.Tx.GrpDepsAll()
		return err
	})
	return s
}

func sameSnapshot(a, b snapshot) bool {
	if len(a.Closure) != len(b.Closure) || len(a.Deps) != len(b.Deps) {
		return false
	}
	for g, rows := range a.Effective {
		if len(rows) != len(b.Effective[g]) {
			return false
		}
		for i := range rows {
			if rows[i].Identity != b.Effective[g][i].Identity || rows[i].Support != b.Effective[g][i].Support {
				return false
			}
		}
	}
	for g, n := range a.Counts {
		if b.Counts[g] != n {
			return false
		}
	}
	for i := range a.Closure {
		if a.Closure[i] != b.Closure[i] {
			return false
		}
	}
	nonzero := func(ls []store.GrpLevel) map[store.GroupID]int {
		m := map[store.GroupID]int{}
		for _, l := range ls {
			if l.Level != 0 {
				m[l.Group] = l.Level
			}
		}
		return m
	}
	la, lb := nonzero(a.Levels), nonzero(b.Levels)
	if len(la) != len(lb) {
		return false
	}
	for g, l := range la {
		if lb[g] != l {
			return false
		}
	}
	return slices.Equal(a.Deps, b.Deps)
}

// TestVerify_DetectsAndRepairsInjectedCorruption damages every kind of derived
// row (a missing member, an invented one, a wrong support, a wrong count, a
// closure row, a level and a dependency edge), and verification finds each,
// repairs them all and leaves exactly the state the incremental engine had.
func TestVerify_DetectsAndRepairsInjectedCorruption(t *testing.T) {
	x := newHarness(t, 5, 4, nil)
	a, b, c, d, comp := x.groups[0], x.groups[1], x.groups[2], x.groups[3], x.groups[4]
	i0, i1, i2, i3 := x.idents[0], x.idents[1], x.idents[2], x.idents[3]
	x.addIdentity(d, i0)
	x.addIdentity(d, i1)
	x.addIdentity(c, i1)
	x.addIdentity(c, i2)
	for _, e := range [][2]store.GroupID{{b, d}, {b, c}, {a, b}} {
		if err := x.addGroup(e[0], e[1]); err != nil {
			t.Fatal(err)
		}
	}
	x.must(func(e model.Env) error {
		_, _, err := e.ConvertToComposite(comp, model.CompositeInput{Op: store.CompComplement, Factors: []store.GroupID{a, c}})
		return err
	})
	want := x.snapshot()
	x.verifyClean()

	list := x.list()
	x.must(func(e model.Env) error {
		tx := e.Tx
		steps := []error{
			tx.DeleteGrpEffective(b, list, i0),           // a member missing
			tx.SetGrpEffective(a, list, i3, 1, x.now),    // a member that should not be
			tx.SetGrpEffective(b, list, i1, 5, x.now),    // a wrong support
			tx.SetGrpEffective(comp, list, i2, 1, x.now), // a composite member that should not be
			tx.AddGrpEffectiveCount(c, 7),                // a wrong cached count
			tx.AddGrpClosure(d, a, 1, 1),                 // a closure row nothing supports
			tx.SubGrpClosure(a, d, 1),                    // a closure row with a path missing
			tx.SetGrpLevel(b, 9),                         // a wrong level
			tx.DeleteGrpDep(store.GrpDep{Parent: a, Child: b, Kind: store.DepNest, List: list}), // a missing edge
			tx.InsertGrpDep(store.GrpDep{Parent: d, Child: c, Kind: store.DepNest, List: list}), // an edge no row backs
		}
		for i, err := range steps {
			if err != nil {
				t.Fatalf("injecting corruption %d: %v", i, err)
			}
		}
		return nil
	})
	if sameSnapshot(want, x.snapshot()) {
		t.Fatal("the injected corruption changed nothing")
	}
	var report *engine.VerifyReport
	x.must(func(e model.Env) error {
		var err error
		report, err = x.eng.Verify(e.Tx, x.now)
		return err
	})
	kinds := map[string]bool{}
	for _, r := range report.Repairs {
		kinds[r.Kind] = true
	}
	for _, k := range []string{"dep", "closure", "level", "effective", "count"} {
		if !kinds[k] {
			t.Errorf("no %q repair reported: %+v", k, report.Repairs)
		}
	}
	if report.RepairCount < 10 || x.eng.Repairs() != int64(report.RepairCount) {
		t.Errorf("repair count %d (counter %d), want at least the 10 injected", report.RepairCount, x.eng.Repairs())
	}
	if got := x.snapshot(); !sameSnapshot(want, got) {
		t.Errorf("the repaired state differs from the incremental one:\nwant %+v\ngot  %+v", want, got)
	}
	x.verifyClean()
	// and the repair is on the audit ledger
	x.read(func(e model.Env) error {
		evs, err := e.Tx.AuditEvents(store.AuditFilter{Limit: 20})
		if err != nil {
			return err
		}
		found := false
		for _, ev := range evs {
			found = found || ev.Action == "groups.engine.repaired"
		}
		if !found {
			t.Error("no groups.engine.repaired audit event")
		}
		return nil
	})
}

// TestModel_CompositeRules covers what the API refuses.
func TestModel_CompositeRules(t *testing.T) {
	x := newHarness(t, 4, 2, nil)
	a, b, c, d := x.groups[0], x.groups[1], x.groups[2], x.groups[3]
	alice := x.idents[0]
	x.addIdentity(a, alice)
	conv := func(g store.GroupID, op store.CompositeOp, discard bool, fs ...store.GroupID) error {
		return x.run(func(e model.Env) error {
			_, _, err := e.ConvertToComposite(g, model.CompositeInput{Op: op, Factors: fs, DiscardMembers: discard})
			return err
		})
	}
	// a group with direct members is not converted unless they are discarded
	me := wantCode(t, conv(a, store.CompUnion, false, b, c), model.Conflict, "has_direct_members")
	if me.Extra["direct_members"] != 1 {
		t.Errorf("extra = %v", me.Extra)
	}
	wantCode(t, conv(d, store.CompComplement, false, a, b, c), model.Invalid, "invalid_composite")
	wantCode(t, conv(d, store.CompUnion, false, a), model.Invalid, "invalid_composite")
	wantCode(t, conv(d, store.CompUnion, false, a, a), model.Invalid, "duplicate_factor")
	wantCode(t, conv(d, "xor", false, a, b), model.Invalid, "invalid_composite")
	if err := conv(d, store.CompUnion, false, a, b); err != nil {
		t.Fatal(err)
	}
	if x.support(d, alice) != 1 {
		t.Error("the composite should hold alice through its factor")
	}
	// a composite takes no direct members, and cannot be converted again
	err := x.run(func(e model.Env) error { _, err := e.AddMember(d, model.MemberInput{Identity: &alice}); return err })
	wantCode(t, err, model.Conflict, "composite_no_members")
	wantCode(t, conv(d, store.CompUnion, false, a, b), model.Conflict, "not_basic")
	// discarding makes the conversion
	if err := conv(a, store.CompIntersection, true, b, c); err != nil {
		t.Fatal(err)
	}
	if x.support(a, alice) != 0 || x.support(d, alice) != 0 {
		t.Error("alice should be gone from the converted group and from the composite that used it")
	}
	x.verifyClean()
	// redefinition, and a composite created as one
	if err := x.run(func(e model.Env) error {
		_, _, err := e.SetComposite(d, model.CompositeInput{Op: store.CompUnion, Factors: []store.GroupID{b, c}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, x.run(func(e model.Env) error {
		_, _, err := e.SetComposite(b, model.CompositeInput{Op: store.CompUnion, Factors: []store.GroupID{b, c}})
		return err
	}), model.Conflict, "not_composite")
	x.must(func(e model.Env) error {
		root, err := e.Tx.GrpRootFolder()
		if err != nil {
			return err
		}
		g, err := e.CreateGroup(model.CreateGroupInput{Folder: root.ID, Extension: "made", Definition: store.DefinitionComposite,
			Op: store.CompUnion, Factors: []store.GroupID{b, c}})
		if err != nil {
			return err
		}
		if g.Definition != store.DefinitionComposite || g.CompositeOp == nil || *g.CompositeOp != store.CompUnion {
			t.Errorf("created group = %+v", g)
		}
		return nil
	})
	x.verifyClean()
}

// TestEngine_DeletedGroupIsEmpty: a deleted group has no members and feeds
// none, and restoring it brings them back.
func TestEngine_DeletedGroupIsEmpty(t *testing.T) {
	x := newHarness(t, 2, 1, nil)
	child, parent := x.groups[0], x.groups[1]
	alice := x.idents[0]
	x.addIdentity(child, alice)
	if err := x.addGroup(parent, child); err != nil {
		t.Fatal(err)
	}
	x.must(func(e model.Env) error { return e.DeleteGroup(child) })
	if x.support(child, alice) != 0 || x.support(parent, alice) != 0 {
		t.Error("a deleted group still has members, or still feeds its parent")
	}
	if g := x.group(parent); g.EffectiveCount != 0 {
		t.Errorf("parent count = %d", g.EffectiveCount)
	}
	x.must(func(e model.Env) error { _, err := e.RestoreGroup(child); return err })
	if x.support(child, alice) != 1 || x.support(parent, alice) != 1 {
		t.Error("restoring the group did not bring its members back")
	}
	x.verifyClean()
}
