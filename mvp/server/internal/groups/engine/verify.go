package engine

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Verification (design §6.6) recomputes everything the engine derives from the
// stored inputs and repairs any difference: the dependency edges from the
// direct group rows and composite factors, the closure and the levels from the
// edges, and every group's effective members from the direct rows, in level
// order, so a group is checked against children that are already right. A
// difference is a bug: it is repaired, logged at ERROR, counted and audited.
// It runs nightly per tenant (the Runner) and on demand.

// Repair is one corrected row.
type Repair struct {
	Kind     string // dep | closure | level | effective | count | orphan
	Group    store.GroupID
	List     store.ListID
	Identity int64
	Had      int64
	Want     int64
}

// VerifyReport is the result of Verify. Repairs lists the first maxRepairsListed.
type VerifyReport struct {
	Groups      int
	Checked     int64
	RepairCount int
	Repairs     []Repair
}

const maxRepairsListed = 200

type verifier struct {
	e      *Engine
	tx     *store.TenantTx
	now    time.Time
	report *VerifyReport
}

func (v *verifier) repaired(r Repair) {
	v.report.RepairCount++
	if len(v.report.Repairs) < maxRepairsListed {
		v.report.Repairs = append(v.report.Repairs, r)
	}
}

// Verify recomputes and repairs the tenant's engine state inside tx.
func (e *Engine) Verify(tx *store.TenantTx, now time.Time) (*VerifyReport, error) {
	if err := Touch(tx, now); err != nil {
		return nil, err
	}
	v := &verifier{e: e, tx: tx, now: now, report: &VerifyReport{}}
	groups, err := tx.GrpGroupsAll()
	if err != nil {
		return nil, err
	}
	v.report.Groups = len(groups)
	if err := v.deps(); err != nil {
		return nil, err
	}
	levels, err := v.structure(groups)
	if err != nil {
		return nil, err
	}
	if err := v.effective(groups, levels); err != nil {
		return nil, err
	}
	if err := tx.SetGrpVerifiedAt(now); err != nil {
		return nil, err
	}
	action := "groups.engine.verified"
	if n := v.report.RepairCount; n > 0 {
		action = "groups.engine.repaired"
		e.repairs.Add(int64(n))
		e.log().Error("groups engine: verification found corrupt state and repaired it",
			"tenant", tx.Tenant().String(), "repairs", n, "groups", len(groups))
	}
	return v.report, tx.Audit(now, "groups.engine", action, ojson.Object{
		{Key: "groups", Value: int64(v.report.Groups)}, {Key: "checked", Value: v.report.Checked},
		{Key: "repairs", Value: int64(v.report.RepairCount)}})
}

// deps makes grp_deps equal to the direct group rows (nest edges) and the
// composite factors (factor edges, in the members list).
func (v *verifier) deps() error {
	members := store.MembersListID(v.tx.Tenant())
	want := map[store.GrpDep]bool{}
	nest, err := v.tx.GrpDirectGroupEdges()
	if err != nil {
		return err
	}
	for _, d := range nest {
		want[d] = true
	}
	factors, err := v.tx.GrpFactorsAll()
	if err != nil {
		return err
	}
	for _, f := range factors {
		want[store.GrpDep{Parent: f.Parent, Child: f.Child, Kind: store.DepFactor, List: members}] = true
	}
	have, err := v.tx.GrpDepsAll()
	if err != nil {
		return err
	}
	seen := map[store.GrpDep]bool{}
	for _, d := range have {
		seen[d] = true
		if !want[d] {
			if err := v.tx.DeleteGrpDep(d); err != nil {
				return err
			}
			v.repaired(Repair{Kind: "dep", Group: d.Parent, List: d.List, Had: 1})
		}
	}
	for d := range want {
		if !seen[d] {
			if err := v.tx.InsertGrpDep(d); err != nil {
				return err
			}
			v.repaired(Repair{Kind: "dep", Group: d.Parent, List: d.List, Want: 1})
		}
	}
	return nil
}

type closureEnd struct {
	paths int64
	depth int
}

// structure recomputes the closure and the levels from the edges, repairs the
// stored ones and returns the levels.
func (v *verifier) structure(groups []*store.NativeGroup) (map[store.GroupID]int, error) {
	deps, err := v.tx.GrpDepsAll()
	if err != nil {
		return nil, err
	}
	kids := map[store.GroupID][]store.GroupID{}
	for _, d := range deps {
		if !slices.Contains(kids[d.Parent], d.Child) {
			kids[d.Parent] = append(kids[d.Parent], d.Child)
		}
	}
	memo := map[store.GroupID]map[store.GroupID]closureEnd{}
	state := map[store.GroupID]int{} // 1 visiting, 2 done
	level := map[store.GroupID]int{}
	var walk func(g store.GroupID) (map[store.GroupID]closureEnd, error)
	walk = func(g store.GroupID) (map[store.GroupID]closureEnd, error) {
		switch state[g] {
		case 2:
			return memo[g], nil
		case 1:
			return nil, fmt.Errorf("engine: the dependency graph has a cycle through group %s; it cannot be repaired automatically", g)
		}
		state[g] = 1
		out := map[store.GroupID]closureEnd{}
		lv := -1
		for _, c := range kids[g] {
			sub, err := walk(c)
			if err != nil {
				return nil, err
			}
			lv = max(lv, level[c])
			add := func(d store.GroupID, paths int64, depth int) {
				cur, ok := out[d]
				cur.paths += paths
				if !ok || depth < cur.depth {
					cur.depth = depth
				}
				out[d] = cur
			}
			add(c, 1, 1)
			for d, ce := range sub {
				add(d, ce.paths, 1+ce.depth)
			}
		}
		level[g] = lv + 1
		memo[g], state[g] = out, 2
		return out, nil
	}
	for _, g := range groups {
		if _, err := walk(g.ID); err != nil {
			return nil, err
		}
	}

	stored, err := v.tx.GrpClosureAll()
	if err != nil {
		return nil, err
	}
	have := map[[2]store.GroupID]store.GrpClosureRow{}
	for _, r := range stored {
		have[[2]store.GroupID{r.Ancestor, r.Descendant}] = r
	}
	for a, sub := range memo {
		for d, ce := range sub {
			key := [2]store.GroupID{a, d}
			if r, ok := have[key]; ok && r.Paths == ce.paths && r.MinDepth == ce.depth {
				delete(have, key)
				continue
			}
			had := int64(0)
			if r, ok := have[key]; ok {
				had = r.Paths
				delete(have, key)
				if err := v.tx.DeleteGrpClosure(a, d); err != nil {
					return nil, err
				}
			}
			if err := v.tx.AddGrpClosure(a, d, ce.paths, ce.depth); err != nil {
				return nil, err
			}
			v.repaired(Repair{Kind: "closure", Group: a, Had: had, Want: ce.paths})
		}
	}
	for key, r := range have { // rows no path supports
		if err := v.tx.DeleteGrpClosure(key[0], key[1]); err != nil {
			return nil, err
		}
		v.repaired(Repair{Kind: "closure", Group: key[0], Had: r.Paths})
	}

	lvs, err := v.tx.GrpLevels()
	if err != nil {
		return nil, err
	}
	have2 := map[store.GroupID]int{}
	for _, l := range lvs {
		have2[l.Group] = l.Level
	}
	for _, g := range groups {
		if want := level[g.ID]; have2[g.ID] != want {
			if err := v.tx.SetGrpLevel(g.ID, want); err != nil {
				return nil, err
			}
			v.repaired(Repair{Kind: "level", Group: g.ID, Had: int64(have2[g.ID]), Want: int64(want)})
		}
	}
	return level, nil
}

// effective recomputes every group's members in level order.
func (v *verifier) effective(groups []*store.NativeGroup, level map[store.GroupID]int) error {
	known := map[store.GroupID]bool{}
	for _, g := range groups {
		known[g.ID] = true
	}
	pairs, err := v.tx.GrpEffectivePairs()
	if err != nil {
		return err
	}
	extra := map[store.GroupID][]store.ListID{}
	for _, p := range pairs {
		if !known[p.Parent] {
			if err := v.tx.DeleteGrpEffectiveOf(p.Parent); err != nil {
				return err
			}
			v.repaired(Repair{Kind: "orphan", Group: p.Parent, List: p.List})
			continue
		}
		extra[p.Parent] = append(extra[p.Parent], p.List)
	}
	order := slices.Clone(groups)
	slices.SortStableFunc(order, func(a, b *store.NativeGroup) int {
		if level[a.ID] != level[b.ID] {
			return level[a.ID] - level[b.ID]
		}
		if a.ID < b.ID {
			return -1
		}
		return 1
	})
	members := store.MembersListID(v.tx.Tenant())
	for _, gr := range order {
		m, err := loadMeta(v.tx, v.now, gr.ID)
		if err != nil {
			return err
		}
		ls, err := lists(v.tx, gr.ID)
		if err != nil {
			return err
		}
		for _, l := range extra[gr.ID] {
			if !slices.Contains(ls, l) {
				ls = append(ls, l)
			}
		}
		r := newRun(v.tx, v.now)
		for _, l := range ls {
			var after int64 = math.MinInt64
			for {
				ids, exhausted, err := candidates(v.tx, gr.ID, l, after, v.e.chunk())
				if err != nil {
					return err
				}
				for _, id := range ids {
					want, err := r.truth(m, l, id)
					if err != nil {
						return err
					}
					had, err := v.tx.GrpEffectiveSupport(gr.ID, l, id)
					if err != nil {
						return err
					}
					v.report.Checked++
					if want == had {
						continue
					}
					if want > 0 {
						err = v.tx.SetGrpEffective(gr.ID, l, id, want, v.now)
					} else {
						err = v.tx.DeleteGrpEffective(gr.ID, l, id)
					}
					if err != nil {
						return err
					}
					v.repaired(Repair{Kind: "effective", Group: gr.ID, List: l, Identity: id, Had: int64(had), Want: int64(want)})
				}
				if exhausted {
					break
				}
				after = ids[len(ids)-1]
			}
		}
		n, err := v.tx.GrpEffectiveCount(gr.ID, members)
		if err != nil {
			return err
		}
		if int64(n) != gr.EffectiveCount {
			if err := v.tx.SetGrpEffectiveCount(gr.ID, int64(n)); err != nil {
				return err
			}
			v.repaired(Repair{Kind: "count", Group: gr.ID, Had: gr.EffectiveCount, Want: int64(n)})
		}
	}
	return nil
}
