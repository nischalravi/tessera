package engine

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// gl is a (group, list) pair: one membership set.
type gl struct {
	g store.GroupID
	l store.ListID
}

// run is one propagation: the seeds waiting at each level, the caches for the
// groups it meets and the changes it has made.
type run struct {
	tx      *store.TenantTx
	now     time.Time
	members store.ListID
	metas   map[store.GroupID]*gmeta
	levels  map[store.GroupID]int
	parents map[gl][]store.GroupID
	pending map[int]map[gl]map[int64]struct{}
	out     []Change
	net     map[store.GroupID]int64 // change of the members-list count, per group
	touched map[store.GroupID]bool
	steps   int
}

func newRun(tx *store.TenantTx, now time.Time) *run {
	return &run{tx: tx, now: now, members: store.MembersListID(tx.Tenant()),
		metas: map[store.GroupID]*gmeta{}, levels: map[store.GroupID]int{}, parents: map[gl][]store.GroupID{},
		pending: map[int]map[gl]map[int64]struct{}{}, net: map[store.GroupID]int64{}, touched: map[store.GroupID]bool{}}
}

func (r *run) meta(id store.GroupID) (*gmeta, error) {
	if m, ok := r.metas[id]; ok {
		return m, nil
	}
	m, err := loadMeta(r.tx, r.now, id)
	if err != nil {
		return nil, fmt.Errorf("engine: group %s: %w", id, err)
	}
	r.metas[id] = m
	return m, nil
}

func (r *run) level(id store.GroupID) (int, error) {
	if lv, ok := r.levels[id]; ok {
		return lv, nil
	}
	lv, err := r.tx.GrpLevel(id)
	if err != nil {
		return 0, err
	}
	r.levels[id] = lv
	return lv, nil
}

func (r *run) push(g store.GroupID, l store.ListID, identity int64) error {
	lv, err := r.level(g)
	if err != nil {
		return err
	}
	b := r.pending[lv]
	if b == nil {
		b = map[gl]map[int64]struct{}{}
		r.pending[lv] = b
	}
	set := b[gl{g, l}]
	if set == nil {
		set = map[int64]struct{}{}
		b[gl{g, l}] = set
	}
	set[identity] = struct{}{}
	return nil
}

func (r *run) parentsOf(g store.GroupID, l store.ListID) ([]store.GroupID, error) {
	if ps, ok := r.parents[gl{g, l}]; ok {
		return ps, nil
	}
	ps, err := r.tx.GrpDepParents(g, l)
	if err != nil {
		return nil, err
	}
	r.parents[gl{g, l}] = ps
	return ps, nil
}

// Apply recomputes the seeds' memberships and everything that depends on a
// membership that changed, in ascending level order, inside tx. It returns the
// effective changes (members gained or lost), in processing order.
//
// Seeds name groups of the transaction's tenant; a seed for a group that does
// not exist is an error.
func (e *Engine) Apply(tx *store.TenantTx, now time.Time, seeds []Seed) ([]Change, error) {
	r := newRun(tx, now)
	for _, s := range seeds {
		if err := r.push(s.Group, s.List, s.Identity); err != nil {
			return nil, err
		}
	}
	if err := r.drain(); err != nil {
		return nil, err
	}
	return r.out, r.finish()
}

// maxSteps guards against a corrupt (cyclic) dependency graph, which verify
// would repair but which must not loop a request forever.
const maxSteps = 50_000_000

func (r *run) drain() error {
	for len(r.pending) > 0 {
		lv := -1
		for k := range r.pending {
			if lv < 0 || k < lv {
				lv = k
			}
		}
		bucket := r.pending[lv]
		delete(r.pending, lv)
		keys := make([]gl, 0, len(bucket))
		for k := range bucket {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b gl) int {
			if a.g != b.g {
				return strings.Compare(string(a.g), string(b.g))
			}
			return strings.Compare(string(a.l), string(b.l))
		})
		for _, k := range keys {
			ids := make([]int64, 0, len(bucket[k]))
			for id := range bucket[k] {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			for _, id := range ids {
				if r.steps++; r.steps > maxSteps {
					return fmt.Errorf("engine: propagation did not settle (is the dependency graph cyclic?)")
				}
				if err := r.step(k, id); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// step recomputes one identity in one set, writes the effective row and, when
// the identity entered or left the set, queues its parents.
func (r *run) step(k gl, identity int64) error {
	m, err := r.meta(k.g)
	if err != nil {
		return err
	}
	want, err := r.truth(m, k.l, identity)
	if err != nil {
		return err
	}
	had, err := r.tx.GrpEffectiveSupport(k.g, k.l, identity)
	if err != nil {
		return err
	}
	if want == had {
		return nil
	}
	if want > 0 {
		err = r.tx.SetGrpEffective(k.g, k.l, identity, want, r.now)
	} else {
		err = r.tx.DeleteGrpEffective(k.g, k.l, identity)
	}
	if err != nil {
		return err
	}
	was, is := had > 0, want > 0
	if was == is {
		return nil // only the number of paths changed: nothing above sees it
	}
	r.out = append(r.out, Change{Group: k.g, List: k.l, Identity: identity, Member: is})
	if k.l == r.members {
		r.touched[k.g] = true
		if is {
			r.net[k.g]++
		} else {
			r.net[k.g]--
		}
	}
	parents, err := r.parentsOf(k.g, k.l)
	if err != nil {
		return err
	}
	for _, p := range parents {
		if err := r.push(p, k.l, identity); err != nil {
			return err
		}
	}
	return nil
}

// finish writes the cached member counts and bumps effective_version of every
// group whose membership changed.
func (r *run) finish() error {
	ids := make([]store.GroupID, 0, len(r.touched))
	for g := range r.touched {
		ids = append(ids, g)
	}
	slices.Sort(ids)
	for _, g := range ids {
		if err := r.tx.AddGrpEffectiveCount(g, r.net[g]); err != nil {
			return err
		}
	}
	return nil
}

// truth is the support an identity should have in a set right now: for a
// basic group the number of active direct paths (§6.2 I1), for a composite
// 1 or 0 by its operator, and 0 for a group that is not live.
func (r *run) truth(m *gmeta, l store.ListID, identity int64) (int32, error) {
	if !m.live {
		return 0, nil
	}
	if m.g.Definition == store.DefinitionBasic {
		return r.tx.GrpBasicSupport(m.g.ID, l, identity, r.now)
	}
	in := make([]bool, len(m.factors))
	for i, f := range m.factors {
		n, err := r.tx.GrpEffectiveSupport(f, l, identity)
		if err != nil {
			return 0, err
		}
		in[i] = n > 0
	}
	if Eval(m.op, in) {
		return 1, nil
	}
	return 0, nil
}
