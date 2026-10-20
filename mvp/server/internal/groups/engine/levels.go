package engine

import (
	"errors"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

// refreshLevels recomputes level(g) = 1 + max(level(child)), leaves 0, for g
// and for every group that depends on it (§6.2 I2). Those are the only groups
// an edge change under g can affect. A group with fewer descendants cannot
// depend on one with more, so ascending descendant count is a valid order.
func refreshLevels(tx *store.TenantTx, g store.GroupID) error {
	anc, err := ancestorsOf(tx, g)
	if err != nil {
		return err
	}
	type node struct {
		id    store.GroupID
		below int
	}
	nodes := make([]node, len(anc))
	for i, a := range anc {
		rows, err := tx.GrpClosureDescendants(a.id)
		if err != nil {
			return err
		}
		nodes[i] = node{a.id, len(rows)}
	}
	slices.SortStableFunc(nodes, func(x, y node) int { return x.below - y.below })
	for _, n := range nodes {
		max, err := tx.GrpMaxChildLevel(n.id)
		if err != nil {
			return err
		}
		cur, err := tx.GrpLevel(n.id)
		if err != nil {
			return err
		}
		if want := max + 1; want != cur {
			if err := tx.SetGrpLevel(n.id, want); err != nil {
				return err
			}
		}
	}
	return nil
}
