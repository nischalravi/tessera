package attrs

import (
	"slices"
	"sort"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Implication closures (G-44, G-45). A name implies other names of its
// definition (an assignment of the first is also one of the others), and an
// action implies other actions. The direct edges are what a person sets; the
// closure (every name reachable through them) is stored beside them in
// grp_attr_name_implies and grp_attr_action_implies and rebuilt, for the whole
// definition, after every change of an edge, a name or an action. A
// definition's names are few, so the rebuild is cheap and cannot drift.

// edges maps a node to the nodes it directly implies.
type edges map[string][]string

// closure returns, for each node, every node reachable from it (not itself,
// unless the graph has a cycle, which setEdges refuses).
func closure(g edges) map[string][]string {
	out := make(map[string][]string, len(g))
	for from := range g {
		seen := map[string]bool{}
		stack := slices.Clone(g[from])
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[n] {
				continue
			}
			seen[n] = true
			stack = append(stack, g[n]...)
		}
		reach := make([]string, 0, len(seen))
		for n := range seen {
			reach = append(reach, n)
		}
		sort.Strings(reach)
		out[from] = reach
	}
	return out
}

// findCycle returns a path that closes a cycle (first node repeated at the
// end), or nil.
func findCycle(g edges) []string {
	const (
		white, grey, black = 0, 1, 2
	)
	state := map[string]int{}
	var path []string
	var visit func(n string) []string
	visit = func(n string) []string {
		state[n] = grey
		path = append(path, n)
		for _, m := range g[n] {
			switch state[m] {
			case grey:
				i := slices.Index(path, m)
				return append(slices.Clone(path[i:]), m)
			case white:
				if c := visit(m); c != nil {
					return c
				}
			}
		}
		path = path[:len(path)-1]
		state[n] = black
		return nil
	}
	nodes := make([]string, 0, len(g))
	for n := range g {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	for _, n := range nodes {
		if state[n] == white {
			if c := visit(n); c != nil {
				return c
			}
		}
	}
	return nil
}

// loadEdges reads a definition's direct edges.
func loadEdges(tx *store.TenantTx, kind, def string) (edges, error) {
	rows, err := tx.GrpAttrImpliesOfDef(kind, def)
	if err != nil {
		return nil, err
	}
	g := edges{}
	for _, r := range rows {
		if r.Direct {
			g[r.From] = append(g[r.From], r.To)
		}
	}
	return g, nil
}

// writeClosure stores the direct edges of g and their closure for a definition.
func writeClosure(tx *store.TenantTx, kind, def string, g edges) error {
	direct := map[[2]string]bool{}
	for from, tos := range g {
		for _, to := range tos {
			direct[[2]string{from, to}] = true
		}
	}
	var rows []store.GrpAttrImplies
	cl := closure(g)
	froms := make([]string, 0, len(cl))
	for from := range cl {
		froms = append(froms, from)
	}
	sort.Strings(froms)
	for _, from := range froms {
		for _, to := range cl[from] {
			rows = append(rows, store.GrpAttrImplies{DefID: def, From: from, To: to, Direct: direct[[2]string{from, to}]})
		}
	}
	return tx.ReplaceGrpAttrImplies(kind, def, rows)
}

// setEdges replaces the direct edges out of one node of a definition (names or
// actions, by kind) and rebuilds the closure. members are the ids of the
// definition's nodes, which every target must be one of. A target that would
// close a cycle is a 409 cycle with the path.
func (e Env) setEdges(kind, def, from string, to []string, members map[string]bool) error {
	seen := map[string]bool{}
	var targets []string
	for _, t := range to {
		switch {
		case t == from:
			return invalid("invalid_implies", "a %s cannot imply itself", kind)
		case !members[t]:
			return invalid("invalid_implies", "%s is not a %s of this definition", t, kind)
		case seen[t]:
			continue
		}
		seen[t] = true
		targets = append(targets, t)
	}
	slices.Sort(targets)
	g, err := loadEdges(e.Tx, kind, def)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		delete(g, from)
	} else {
		g[from] = targets
	}
	if c := findCycle(g); c != nil {
		return withExtra(conflict("cycle", "the implication would make %s imply itself", kind), "path", c)
	}
	return writeClosure(e.Tx, kind, def, g)
}

// dropNode removes a node (a name or an action about to be deleted) from the
// edges of its definition and rebuilds the closure.
func (e Env) dropNode(kind, def, node string) error {
	g, err := loadEdges(e.Tx, kind, def)
	if err != nil {
		return err
	}
	delete(g, node)
	for from, tos := range g {
		g[from] = slices.DeleteFunc(slices.Clone(tos), func(t string) bool { return t == node })
		if len(g[from]) == 0 {
			delete(g, from)
		}
	}
	return writeClosure(e.Tx, kind, def, g)
}

// Implied returns what a name (kind names) or an action (kind actions) implies:
// its direct targets and the whole closure, each sorted.
func Implied(tx *store.TenantTx, kind, id string) (direct, all []string, err error) {
	rows, err := tx.GrpAttrImpliesOf(kind, id)
	if err != nil {
		return nil, nil, err
	}
	direct, all = []string{}, []string{}
	for _, r := range rows {
		all = append(all, r.To)
		if r.Direct {
			direct = append(direct, r.To)
		}
	}
	return direct, all, nil
}

func impliesDetail(kind, id string, to []string, closureSize int) ojson.Object {
	return ojson.Object{{Key: "kind", Value: kind}, {Key: "id", Value: id}, {Key: "implies", Value: to},
		{Key: "closure_size", Value: closureSize}}
}
