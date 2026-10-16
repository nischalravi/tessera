package engine_test

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A naive in-memory model of design §6.1, evaluated from scratch: the oracle
// the incremental engine is compared with.

type oRow struct {
	ident    int // identity index, or -1 for a group row
	grp      int // group index of a group row
	from, to *time.Time
}

type oGroup struct {
	composite bool
	op        store.CompositeOp
	factors   []int
	rows      []oRow
	status    string
	from, to  *time.Time
}

type oracle struct {
	gs   []oGroup
	now  time.Time
	idN  int
	wake time.Time // the time of the last wheel tick
}

func newOracle(nGroups, nIdents int) *oracle {
	o := &oracle{gs: make([]oGroup, nGroups), now: t0, idN: nIdents, wake: t0}
	for i := range o.gs {
		o.gs[i].status = store.GroupActive
	}
	return o
}

func (o *oracle) live(g int) bool {
	x := o.gs[g]
	return x.status == store.GroupActive && (x.from == nil || !x.from.After(o.now)) && (x.to == nil || o.now.Before(*x.to))
}

func (o *oracle) active(r oRow) bool {
	return (r.from == nil || !r.from.After(o.now)) && (r.to == nil || o.now.Before(*r.to))
}

// in reports whether identity i is a member of group g.
func (o *oracle) in(g, i int) bool {
	if !o.live(g) {
		return false
	}
	x := o.gs[g]
	if x.composite {
		in := make([]bool, len(x.factors))
		for k, f := range x.factors {
			in[k] = o.in(f, i)
		}
		switch x.op {
		case store.CompIntersection:
			for _, v := range in {
				if !v {
					return false
				}
			}
			return true
		case store.CompComplement:
			return in[0] && !in[1]
		}
		for _, v := range in {
			if v {
				return true
			}
		}
		return false
	}
	return o.support(g, i) > 0
}

// support is the stored support: active direct paths for a basic group, 0/1 for a composite.
func (o *oracle) support(g, i int) int {
	if !o.live(g) {
		return 0
	}
	x := o.gs[g]
	if x.composite {
		if o.in(g, i) {
			return 1
		}
		return 0
	}
	n := 0
	for _, r := range x.rows {
		if !o.active(r) {
			continue
		}
		if r.ident == i || (r.ident < 0 && o.in(r.grp, i)) {
			n++
		}
	}
	return n
}

// children are the groups g depends on, whatever the dates.
func (o *oracle) children(g int) []int {
	x := o.gs[g]
	if x.composite {
		return x.factors
	}
	var out []int
	for _, r := range x.rows {
		if r.ident < 0 {
			out = append(out, r.grp)
		}
	}
	return out
}

// reaches reports whether from depends on to, directly or not.
func (o *oracle) reaches(from, to int) bool {
	seen := map[int]bool{}
	var walk func(int) bool
	walk = func(g int) bool {
		for _, c := range o.children(g) {
			if c == to || (!seen[c] && func() bool { seen[c] = true; return walk(c) }()) {
				return true
			}
		}
		return false
	}
	return walk(from)
}

func (o *oracle) cycle(parent, child int) bool { return parent == child || o.reaches(child, parent) }

func (o *oracle) advance(d time.Duration) {
	prev := o.now
	o.now = o.now.Add(d)
	for i := range o.gs {
		x := &o.gs[i]
		if x.to != nil && x.to.After(prev) && !x.to.After(o.now) && x.status == store.GroupActive {
			x.status = store.GroupDisabled
		}
	}
}

func (o *oracle) findRow(g int, ident, grp int) int {
	for k, r := range o.gs[g].rows {
		if (ident >= 0 && r.ident == ident) || (ident < 0 && r.ident < 0 && r.grp == grp) {
			return k
		}
	}
	return -1
}

// randomDates draws a membership's dates relative to now.
func randomDates(rng *rand.Rand, now time.Time) (from, to *time.Time) {
	at := func(lo, hi int) *time.Time {
		t := now.Add(time.Duration(lo+rng.Intn(hi-lo+1)) * time.Second)
		return &t
	}
	switch rng.Intn(5) {
	case 1:
		from = at(1, 100)
	case 2:
		to = at(1, 100)
	case 3:
		from, to = at(-50, 0), at(1, 100)
	case 4:
		from = at(1, 50)
		to = at(51, 150)
	}
	return from, to
}

func codeOf(err error) string {
	var me *model.Error
	if errors.As(err, &me) {
		return me.Code
	}
	return ""
}

// runOracle applies random operations to the engine (through the model, the
// way the API does) and to the oracle, and compares every group and identity
// after each batch. It finishes with a full verification, which recomputes the
// closure, the levels and every effective row and must find nothing to repair.
func runOracle(t testing.TB, seed int64, steps int) {
	rng := rand.New(rand.NewSource(seed))
	nG, nI := 5+rng.Intn(4), 4+rng.Intn(3)
	budget := 0
	if rng.Intn(3) == 0 {
		budget = 1 + rng.Intn(6) // tiny: most recomputes go through the queue
	}
	eng := engine.New(budget)
	eng.Chunk = 1 + rng.Intn(4)
	x := newHarness(t, nG, nI, eng)
	o := newOracle(nG, nI)
	live := func(g int) bool { return o.gs[g].status != store.GroupDeleted }
	fail := func(step int, format string, args ...any) {
		t.Helper()
		t.Fatalf("seed %d step %d: %s", seed, step, fmt.Sprintf(format, args...))
	}
	for step := 0; step < steps; step++ {
		g, h := rng.Intn(nG), rng.Intn(nG)
		ident := rng.Intn(nI)
		switch op := rng.Intn(13); op {
		case 0, 1, 2: // add or update an identity row
			if !live(g) || o.gs[g].composite {
				continue
			}
			from, to := randomDates(rng, o.now)
			id := x.idents[ident]
			err := x.run(func(e model.Env) error {
				_, err := e.AddMember(x.groups[g], model.MemberInput{Identity: &id, EnabledFrom: from, DisabledAt: to})
				return err
			})
			if from != nil && to != nil && !to.After(*from) {
				continue
			}
			if err != nil {
				fail(step, "add identity: %v", err)
			}
			if k := o.findRow(g, ident, 0); k >= 0 {
				o.gs[g].rows[k].from, o.gs[g].rows[k].to = from, to
			} else {
				o.gs[g].rows = append(o.gs[g].rows, oRow{ident: ident, from: from, to: to})
			}
		case 3: // remove an identity row
			k := o.findRow(g, ident, 0)
			if k < 0 || !live(g) {
				continue
			}
			id := x.idents[ident]
			if err := x.run(func(e model.Env) error {
				_, err := e.RemoveMember(x.groups[g], fmt.Sprint(id))
				return err
			}); err != nil {
				fail(step, "remove identity: %v", err)
			}
			o.gs[g].rows = append(o.gs[g].rows[:k], o.gs[g].rows[k+1:]...)
		case 4, 5, 6: // add a group row
			if !live(g) || !live(h) || o.gs[g].composite {
				continue
			}
			from, to := randomDates(rng, o.now)
			err := x.run(func(e model.Env) error {
				_, err := e.AddMember(x.groups[g], model.MemberInput{Group: x.groups[h], EnabledFrom: from, DisabledAt: to})
				return err
			})
			k := o.findRow(g, -1, h)
			switch {
			case from != nil && to != nil && !to.After(*from):
				continue
			case k < 0 && o.cycle(g, h):
				if codeOf(err) != "cycle" {
					fail(step, "nesting %d in %d: err = %v, want a cycle", h, g, err)
				}
				continue
			case err != nil:
				fail(step, "add group: %v", err)
			case k >= 0:
				o.gs[g].rows[k].from, o.gs[g].rows[k].to = from, to
			default:
				o.gs[g].rows = append(o.gs[g].rows, oRow{ident: -1, grp: h, from: from, to: to})
			}
		case 7: // remove a group row
			k := o.findRow(g, -1, h)
			if k < 0 || !live(g) {
				continue
			}
			if err := x.run(func(e model.Env) error {
				_, err := e.RemoveMember(x.groups[g], string(x.groups[h]))
				return err
			}); err != nil {
				fail(step, "remove group: %v", err)
			}
			o.gs[g].rows = append(o.gs[g].rows[:k], o.gs[g].rows[k+1:]...)
		case 8, 9: // convert to composite, or redefine one
			if !live(g) {
				continue
			}
			cop := []store.CompositeOp{store.CompUnion, store.CompIntersection, store.CompComplement}[rng.Intn(3)]
			n := 2
			if cop != store.CompComplement {
				n += rng.Intn(2)
			}
			var fs []int
			var ids []store.GroupID
			for _, f := range rng.Perm(nG) {
				if len(fs) < n && live(f) {
					fs = append(fs, f)
					ids = append(ids, x.groups[f])
				}
			}
			if len(fs) < n {
				continue
			}
			cyc := false
			for _, f := range fs {
				cyc = cyc || o.cycle(g, f)
			}
			err := x.run(func(e model.Env) error {
				var err error
				if o.gs[g].composite {
					_, _, err = e.SetComposite(x.groups[g], model.CompositeInput{Op: cop, Factors: ids})
				} else {
					_, _, err = e.ConvertToComposite(x.groups[g], model.CompositeInput{Op: cop, Factors: ids, DiscardMembers: true})
				}
				return err
			})
			if cyc {
				if codeOf(err) != "cycle" {
					fail(step, "composite %d of %v: err = %v, want a cycle", g, fs, err)
				}
				continue
			}
			if err != nil {
				fail(step, "composite: %v", err)
			}
			o.gs[g].composite, o.gs[g].op, o.gs[g].factors, o.gs[g].rows = true, cop, fs, nil
		case 10: // disable or enable
			if !live(g) {
				continue
			}
			st := store.GroupDisabled
			if o.gs[g].status == store.GroupDisabled {
				st = store.GroupActive
			}
			if err := x.run(func(e model.Env) error {
				_, err := e.UpdateGroup(x.groups[g], model.UpdateGroupInput{Status: &st})
				return err
			}); err != nil {
				fail(step, "status: %v", err)
			}
			o.gs[g].status = st
		case 11: // delete or restore
			var err error
			if o.gs[g].status == store.GroupDeleted {
				err = x.run(func(e model.Env) error { _, err := e.RestoreGroup(x.groups[g]); return err })
				o.gs[g].status = store.GroupActive
			} else {
				err = x.run(func(e model.Env) error { return e.DeleteGroup(x.groups[g]) })
				o.gs[g].status = store.GroupDeleted
			}
			if err != nil {
				fail(step, "delete or restore: %v", err)
			}
		case 12: // set a group's dates, or let time pass
			if rng.Intn(2) == 0 && live(g) {
				from, to := randomDates(rng, o.now)
				in := model.UpdateGroupInput{ClearEnabledFrom: from == nil, ClearDisabledAt: to == nil, EnabledFrom: from, DisabledAt: to}
				err := x.run(func(e model.Env) error { _, err := e.UpdateGroup(x.groups[g], in); return err })
				if from != nil && to != nil && !to.After(*from) {
					continue
				}
				if err != nil {
					fail(step, "window: %v", err)
				}
				o.gs[g].from, o.gs[g].to = from, to
			} else {
				d := time.Duration(1+rng.Intn(90)) * time.Second
				o.advance(d)
				x.advance(d)
			}
		}
		if rng.Intn(3) == 0 {
			x.drain() // anything the budget queued
			compare(t, x, o, seed, step)
		}
	}
	x.drain()
	compare(t, x, o, seed, steps)
	x.verifyClean()
}

func compare(t testing.TB, x *harness, o *oracle, seed int64, step int) {
	t.Helper()
	x.read(func(e model.Env) error {
		for g := range o.gs {
			members := 0
			for i := 0; i < o.idN; i++ {
				got, err := e.Tx.GrpEffectiveSupport(x.groups[g], x.list(), x.idents[i])
				if err != nil {
					return err
				}
				if want := o.support(g, i); int(got) != want {
					t.Fatalf("seed %d step %d: group %d identity %d: support %d, oracle %d (now %s, %+v)", seed, step, g, i, got, want, o.now.Format("15:04:05"), o.gs[g])
				}
				ok, err := e.IsMember(x.groups[g], x.idents[i])
				if err != nil {
					return err
				}
				if ok != o.in(g, i) {
					t.Fatalf("seed %d step %d: group %d identity %d: IsMember %v, oracle %v", seed, step, g, i, ok, o.in(g, i))
				}
				if o.in(g, i) {
					members++
				}
			}
			grp, err := e.Group(x.groups[g])
			if err != nil {
				return err
			}
			if int(grp.EffectiveCount) != members || grp.RecomputeState != "clean" {
				t.Fatalf("seed %d step %d: group %d count %d state %s, oracle %d members", seed, step, g, grp.EffectiveCount, grp.RecomputeState, members)
			}
		}
		return nil
	})
}

// TestEngine_MatchesOracle compares the incremental engine with the oracle
// over random DAGs, composites of composites, dates, disabled and deleted
// groups, cycle attempts and a synchronous budget small enough to send most
// work through the queue.
func TestEngine_MatchesOracle(t *testing.T) {
	seeds, steps := 24, 70
	if testing.Short() {
		seeds = 6
	}
	if n, err := strconv.Atoi(os.Getenv("TESSERA_ORACLE_SEEDS")); err == nil && n > 0 {
		seeds = n // a longer soak: TESSERA_ORACLE_SEEDS=500 go test -run MatchesOracle
	}
	for seed := int64(1); seed <= int64(seeds); seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) { runOracle(t, seed, steps) })
	}
}

// FuzzEngine_MatchesOracle is the same comparison under Go's fuzzer
// (go test -fuzz=FuzzEngine_MatchesOracle ./internal/groups/engine).
func FuzzEngine_MatchesOracle(f *testing.F) {
	for _, s := range []int64{1, 7, 42, 99} {
		f.Add(s, uint8(40))
	}
	f.Fuzz(func(t *testing.T, seed int64, steps uint8) {
		runOracle(t, seed, 1+int(steps)%80)
	})
}
