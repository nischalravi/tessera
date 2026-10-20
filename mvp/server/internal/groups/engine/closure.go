package engine

import (
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The dependency graph: an edge Parent <- Child says Child's members feed
// Parent (nesting, or a composite factor). grp_closure is its transitive
// closure with path counts (§6.2 I2), kept incrementally.

// CheckCycle refuses the edge parent <- child when it would close a cycle:
// when child is parent, or parent is already a descendant of child.
func (e *Engine) CheckCycle(tx *store.TenantTx, parent, child store.GroupID) error {
	if parent == child {
		return &CycleError{Parent: parent, Child: child, Path: []store.GroupID{child, parent}}
	}
	if _, err := tx.GrpClosureGet(child, parent); err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	path, err := pathDown(tx, child, parent)
	if err != nil {
		return err
	}
	return &CycleError{Parent: parent, Child: child, Path: path}
}

// pathDown finds a shortest chain of edges from from down to to (breadth
// first), as the list of groups on it. It returns just {from, to} if the
// closure and the edges disagree (verification repairs that).
func pathDown(tx *store.TenantTx, from, to store.GroupID) ([]store.GroupID, error) {
	prev := map[store.GroupID]store.GroupID{from: ""}
	queue := []store.GroupID{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		kids, err := tx.GrpDepChildren(cur, "")
		if err != nil {
			return nil, err
		}
		for _, k := range kids {
			if _, seen := prev[k]; seen {
				continue
			}
			prev[k] = cur
			if k == to {
				var path []store.GroupID
				for at := to; at != ""; at = prev[at] {
					path = append(path, at)
				}
				slices.Reverse(path)
				return path, nil
			}
			queue = append(queue, k)
		}
	}
	return []store.GroupID{from, to}, nil
}

// pathEnd is a group at the end of a path set: id, number of paths and the
// shortest one.
type pathEnd struct {
	id       store.GroupID
	paths    int64
	minDepth int
}

// ancestorsOf is the group and every group that depends on it.
func ancestorsOf(tx *store.TenantTx, g store.GroupID) ([]pathEnd, error) {
	rows, err := tx.GrpClosureAncestors(g)
	if err != nil {
		return nil, err
	}
	out := []pathEnd{{g, 1, 0}}
	for _, r := range rows {
		out = append(out, pathEnd{r.Ancestor, r.Paths, r.MinDepth})
	}
	return out, nil
}

// descendantsOf is the group and every group it depends on.
func descendantsOf(tx *store.TenantTx, g store.GroupID) ([]pathEnd, error) {
	rows, err := tx.GrpClosureDescendants(g)
	if err != nil {
		return nil, err
	}
	out := []pathEnd{{g, 1, 0}}
	for _, r := range rows {
		out = append(out, pathEnd{r.Descendant, r.Paths, r.MinDepth})
	}
	return out, nil
}

// AddEdge adds an edge to the dependency graph and updates the closure and the
// levels. It refuses a cycle with a *CycleError. Adding an edge that exists is
// a no-op. The closure counts one edge per (parent, child) pair, however many
// kinds or lists it has.
func (e *Engine) AddEdge(tx *store.TenantTx, d store.GrpDep) error {
	if err := e.CheckCycle(tx, d.Parent, d.Child); err != nil {
		return err
	}
	pairs, err := tx.GrpDepPairCount(d.Parent, d.Child)
	if err != nil {
		return err
	}
	if err := tx.InsertGrpDep(d); err != nil {
		return err
	}
	if pairs > 0 {
		return nil
	}
	anc, err := ancestorsOf(tx, d.Parent)
	if err != nil {
		return err
	}
	desc, err := descendantsOf(tx, d.Child)
	if err != nil {
		return err
	}
	for _, a := range anc {
		for _, c := range desc {
			if err := tx.AddGrpClosure(a.id, c.id, a.paths*c.paths, a.minDepth+1+c.minDepth); err != nil {
				return err
			}
		}
	}
	return refreshLevels(tx, d.Parent)
}

// RemoveEdge removes an edge and, when it was the last one between its parent
// and child, subtracts its paths from the closure, then refreshes the levels
// and the shortest depths it affected.
func (e *Engine) RemoveEdge(tx *store.TenantTx, d store.GrpDep) error {
	if err := tx.DeleteGrpDep(d); err != nil {
		return err
	}
	pairs, err := tx.GrpDepPairCount(d.Parent, d.Child)
	if err != nil || pairs > 0 {
		return err
	}
	anc, err := ancestorsOf(tx, d.Parent)
	if err != nil {
		return err
	}
	desc, err := descendantsOf(tx, d.Child)
	if err != nil {
		return err
	}
	for _, a := range anc {
		for _, c := range desc {
			if err := tx.SubGrpClosure(a.id, c.id, a.paths*c.paths); err != nil {
				return err
			}
		}
	}
	if err := refreshLevels(tx, d.Parent); err != nil {
		return err
	}
	return fixDepths(tx, anc, desc)
}

// fixDepths recomputes min_depth for the closure rows between the given
// ancestors and descendants after an edge was removed. Ancestors are handled
// children first, so the rows a depth is derived from are already right.
func fixDepths(tx *store.TenantTx, anc, desc []pathEnd) error {
	levels := map[store.GroupID]int{}
	for _, a := range anc {
		lv, err := tx.GrpLevel(a.id)
		if err != nil {
			return err
		}
		levels[a.id] = lv
	}
	order := slices.Clone(anc)
	slices.SortStableFunc(order, func(x, y pathEnd) int { return levels[x.id] - levels[y.id] })
	for _, a := range order {
		rows, err := tx.GrpClosureDescendants(a.id)
		if err != nil {
			return err
		}
		have := map[store.GroupID]int{}
		for _, r := range rows {
			have[r.Descendant] = r.MinDepth
		}
		kids, err := tx.GrpDepChildren(a.id, "")
		if err != nil {
			return err
		}
		best := map[store.GroupID]int{}
		for _, k := range kids {
			if cur, ok := best[k]; !ok || cur > 1 {
				best[k] = 1
			}
			sub, err := tx.GrpClosureDescendants(k)
			if err != nil {
				return err
			}
			for _, r := range sub {
				if cur, ok := best[r.Descendant]; !ok || cur > 1+r.MinDepth {
					best[r.Descendant] = 1 + r.MinDepth
				}
			}
		}
		for _, d := range desc {
			cur, ok := have[d.id]
			if !ok {
				continue
			}
			if want, ok := best[d.id]; ok && want != cur {
				if err := tx.SetGrpClosureDepth(a.id, d.id, want); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
