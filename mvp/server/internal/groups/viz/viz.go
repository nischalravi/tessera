// Package viz is the Groups lens of the access graph (design
// docs/design/groups-grouper-parity.md §10.7; issue #57, GR-14): the dependency
// graph of a group (what it contains, what contains it, up to N levels each
// way) and a person's group graph. Every node is filtered by VIEW: a group the
// subject may not view is not drawn, is not counted, and is not walked through,
// so nothing behind it is revealed (Grouper's GRP-7387 leaked folder names
// through a visualization that skipped this).
package viz

import (
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits.
const (
	MaxLevels = 10
	MaxNodes  = 300
)

// Node is a group or an identity of the graph.
type Node struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // group | identity
	Name   string `json:"name"`
	Status string `json:"status,omitempty"`
	// Level is the distance from the root: negative above it (what contains it),
	// positive below it (what it contains).
	Level int `json:"level"`
}

// Edge says From is a member of To: a group nested in another, a factor of a
// composite, or an identity directly in a group.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // nest | factor | direct
}

// Graph is a lens result. Downstream entitlements and provisioners are not in
// it yet: they arrive with the provisioning framework (GR-11).
type Graph struct {
	Root       string `json:"root"`
	Nodes      []Node `json:"nodes"`
	Edges      []Edge `json:"edges"`
	Truncated  bool   `json:"truncated"`
	Downstream bool   `json:"downstream_available"`
}

type walker struct {
	tx    *store.TenantTx
	ck    *privs.Checker
	list  store.ListID
	nodes map[string]Node
	edges map[Edge]bool
	trunc bool
}

func (w *walker) view(id store.GroupID) (*store.NativeGroup, bool, error) {
	g, err := w.tx.GrpGroup(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && g.Status == store.GroupDeleted) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	ok, err := w.ck.Has(privs.GroupObject(g.ID), privs.View)
	return g, ok, err
}

func (w *walker) add(g *store.NativeGroup, level int) bool {
	id := string(g.ID)
	if _, ok := w.nodes[id]; ok {
		return true
	}
	if len(w.nodes) >= MaxNodes {
		w.trunc = true
		return false
	}
	w.nodes[id] = Node{ID: id, Kind: "group", Name: g.Name, Status: g.Status, Level: level}
	return true
}

func (w *walker) graph(root string) *Graph {
	out := &Graph{Root: root, Nodes: make([]Node, 0, len(w.nodes)), Edges: make([]Edge, 0, len(w.edges)), Truncated: w.trunc}
	for _, n := range w.nodes {
		out.Nodes = append(out.Nodes, n)
	}
	sort.Slice(out.Nodes, func(i, j int) bool {
		a, b := out.Nodes[i], out.Nodes[j]
		if a.Level != b.Level {
			return a.Level < b.Level
		}
		return a.Name+a.ID < b.Name+b.ID
	})
	for e := range w.edges {
		out.Edges = append(out.Edges, e)
	}
	sort.Slice(out.Edges, func(i, j int) bool {
		a, b := out.Edges[i], out.Edges[j]
		return a.From+"|"+a.To+"|"+a.Kind < b.From+"|"+b.To+"|"+b.Kind
	})
	return out
}

// depKind is the edge kind of a stored dependency.
func depKind(k store.DepKind) string {
	if k == store.DepFactor {
		return "factor"
	}
	return "nest"
}

// up adds the groups that contain id, level by level, up to levels.
func (w *walker) up(id store.GroupID, levels, base int) error {
	frontier := []store.GroupID{id}
	for lvl := 1; lvl <= levels && len(frontier) > 0; lvl++ {
		var next []store.GroupID
		for _, child := range frontier {
			parents, err := w.tx.GrpDepParents(child, w.list)
			if err != nil {
				return err
			}
			for _, p := range parents {
				g, ok, err := w.view(p)
				if err != nil {
					return err
				}
				if !ok || !w.add(g, -lvl-base) {
					continue
				}
				deps, err := w.tx.GrpDepsOf(p)
				if err != nil {
					return err
				}
				for _, d := range deps {
					if d.Child == child && d.List == w.list {
						w.edges[Edge{From: string(child), To: string(p), Kind: depKind(d.Kind)}] = true
					}
				}
				next = append(next, p)
			}
		}
		frontier = next
	}
	return nil
}

// down adds the groups id contains, level by level, up to levels.
func (w *walker) down(id store.GroupID, levels int) error {
	frontier := []store.GroupID{id}
	for lvl := 1; lvl <= levels && len(frontier) > 0; lvl++ {
		var next []store.GroupID
		for _, parent := range frontier {
			deps, err := w.tx.GrpDepsOf(parent)
			if err != nil {
				return err
			}
			for _, d := range deps {
				if d.List != w.list {
					continue
				}
				g, ok, err := w.view(d.Child)
				if err != nil {
					return err
				}
				if !ok || !w.add(g, lvl) {
					continue
				}
				w.edges[Edge{From: string(d.Child), To: string(parent), Kind: depKind(d.Kind)}] = true
				next = append(next, d.Child)
			}
		}
		frontier = next
	}
	return nil
}

func checkLevels(n int) error {
	if n < 0 || n > MaxLevels {
		return gov.Invalid("invalid_levels", "up and down are 0 to %d", MaxLevels)
	}
	return nil
}

// GroupGraph returns the dependency graph of a group: up levels of what
// contains it and down levels of what it contains, each node one the subject may
// view. The subject must be able to view the root (404 otherwise: a group one
// may not view is not disclosed).
func GroupGraph(tx *store.TenantTx, ck *privs.Checker, root store.GroupID, up, down int) (*Graph, error) {
	if err := errors.Join(checkLevels(up), checkLevels(down)); err != nil {
		return nil, gov.Invalid("invalid_levels", "up and down are 0 to %d", MaxLevels)
	}
	w := &walker{tx: tx, ck: ck, list: store.MembersListID(tx.Tenant()), nodes: map[string]Node{}, edges: map[Edge]bool{}}
	g, ok, err := w.view(root)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, gov.NotFound("no such group")
	}
	w.add(g, 0)
	if err := w.up(root, up, 0); err != nil {
		return nil, err
	}
	if err := w.down(root, down); err != nil {
		return nil, err
	}
	return w.graph(string(root)), nil
}

// PersonGraph returns an identity's group graph: the groups it is in directly
// (and the identity itself as the root), and the groups that contain those, up
// to levels. Only groups the subject may view are drawn.
func PersonGraph(tx *store.TenantTx, ck *privs.Checker, identity int64, levels int, now time.Time) (*Graph, error) {
	if err := checkLevels(levels); err != nil {
		return nil, err
	}
	who, err := tx.Identity(identity)
	if errors.Is(err, store.ErrNotFound) {
		return nil, gov.NotFound("no such identity")
	}
	if err != nil {
		return nil, err
	}
	w := &walker{tx: tx, ck: ck, list: store.MembersListID(tx.Tenant()), nodes: map[string]Node{}, edges: map[Edge]bool{}}
	root := "identity:" + strconv.FormatInt(identity, 10)
	w.nodes[root] = Node{ID: root, Kind: "identity", Name: who.Name, Status: who.Status, Level: 0}
	direct, err := tx.GrpDirectIdentityGroups(w.list, identity, now)
	if err != nil {
		return nil, err
	}
	for _, id := range direct {
		g, ok, err := w.view(id)
		if err != nil {
			return nil, err
		}
		if !ok || !w.add(g, -1) {
			continue
		}
		w.edges[Edge{From: root, To: string(g.ID), Kind: "direct"}] = true
		if levels > 1 {
			if err := w.up(id, levels-1, 1); err != nil {
				return nil, err
			}
		}
	}
	return w.graph(root), nil
}
