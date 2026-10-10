// Package graph computes effective permissions.
//
// The graph is a directed graph whose node keys are strings:
//
//	identity:<id> -> account:<id> -> group:<id> (-> group:<id> ...) -> perm:<id>
//
// Permission nodes carry their resource as attributes (resource nodes also
// exist for visualization, linked perm -> resource). Effective permissions are
// every perm node reachable from an identity, together with the simple paths
// that grant it, so the UI can explain "why does alice have s3:GetObject on
// customer-pii?".
//
// A Snapshot is cheap to copy, which is what makes what-if simulation
// possible: copy, add/remove edges, recompute, diff. Node and successor order
// is insertion order (identities, resources, accounts, groups, permissions,
// then grant edges in id order), which keeps every result deterministic.
package graph

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// MaxPathsPerPermission caps the number of paths kept per permission.
const MaxPathsPerPermission = 8

// Node is a graph node. Which fields are meaningful depends on Kind.
type Node struct {
	Key          string
	Kind         string // identity | resource | account | group | perm
	Label        string
	ID           int64
	System       string // "" for identities
	Type         string // identity type
	Status       string // identity / account status
	Department   *string
	Environment  *string  // resource / perm
	Tags         []string // resource / perm
	Privileged   bool     // group / perm
	Requestable  bool     // group
	Name         string   // group
	Action       string   // perm
	ResourceID   int64    // perm
	ResourceName string   // perm
	AccountKind  string
	GroupKind    string
	ResourceKind string
	IdentityID   *int64 // account
}

// Edge carries the attributes of a directed edge.
type Edge struct {
	Relation  string
	EdgeID    *int64 // grant_edges id; nil for structural or simulated edges
	Source    string // connector | jit | manual | simulated
	ExpiresAt *time.Time
}

// EffectivePermission is one permission an identity can exercise, with the
// paths that grant it.
type EffectivePermission struct {
	PermKey      string
	PermID       int64
	Action       string
	System       string
	Privileged   bool
	ResourceID   int64
	ResourceName string
	Environment  *string
	Tags         []string
	Paths        [][]string
	// Standing is true when at least one path consists only of non-JIT grants.
	Standing bool
}

// JITOnly reports whether the permission is reachable only through JIT grants.
func (e *EffectivePermission) JITOnly() bool { return !e.Standing }

// Eff is an insertion-ordered map of perm key -> effective permission.
type Eff struct {
	Keys []string
	M    map[string]*EffectivePermission
}

// Len is the number of permissions.
func (e *Eff) Len() int { return len(e.Keys) }

// Values returns permissions in discovery order.
func (e *Eff) Values() []*EffectivePermission {
	out := make([]*EffectivePermission, len(e.Keys))
	for i, k := range e.Keys {
		out[i] = e.M[k]
	}
	return out
}

// Has reports whether perm key k is present.
func (e *Eff) Has(k string) bool { _, ok := e.M[k]; return ok }

type edgeKey struct{ src, dst string }

// Snapshot is an in-memory graph.
type Snapshot struct {
	order []string
	nodes map[string]*Node
	succ  map[string][]string
	edges map[edgeKey]*Edge
	eff   map[int64]*Eff
}

// New returns an empty snapshot.
func New() *Snapshot {
	return &Snapshot{nodes: map[string]*Node{}, succ: map[string][]string{}, edges: map[edgeKey]*Edge{}, eff: map[int64]*Eff{}}
}

// Key builds a node key such as "group:7".
func Key(kind string, id int64) string { return kind + ":" + strconv.FormatInt(id, 10) }

// ParseKey splits "group:7" into ("group", 7).
func ParseKey(key string) (string, int64, error) {
	kind, raw, _ := strings.Cut(key, ":")
	id, err := strconv.ParseInt(raw, 10, 64)
	return kind, id, err
}

// AddNode adds (or replaces the attributes of) a node.
func (g *Snapshot) AddNode(n *Node) {
	if _, ok := g.nodes[n.Key]; !ok {
		g.order = append(g.order, n.Key)
	}
	g.nodes[n.Key] = n
}

// setEdge adds an edge or updates the attributes of an existing one in place.
func (g *Snapshot) setEdge(src, dst string, e *Edge) {
	for _, k := range []string{src, dst} {
		if _, ok := g.nodes[k]; !ok {
			g.AddNode(&Node{Key: k})
		}
	}
	k := edgeKey{src, dst}
	if _, ok := g.edges[k]; !ok {
		g.succ[src] = append(g.succ[src], dst)
	}
	g.edges[k] = e
}

// Build builds the live graph of the transaction's tenant. Expired JIT edges
// are excluded. The snapshot is per-tenant by construction: its only input is
// a tenant transaction, so another tenant's node keys are unknown nodes.
func Build(c *store.TenantTx, now time.Time) (*Snapshot, error) {
	g := New()
	idents, err := c.Identities()
	if err != nil {
		return nil, err
	}
	for _, i := range idents {
		g.AddNode(&Node{Key: Key("identity", i.ID), Kind: "identity", Label: i.Name, ID: i.ID, Type: i.Type,
			Status: i.Status, Department: i.Department})
	}
	resources, err := c.Resources()
	if err != nil {
		return nil, err
	}
	for _, r := range resources {
		g.AddNode(&Node{Key: Key("resource", r.ID), Kind: "resource", Label: r.Name, ID: r.ID, System: r.System,
			Environment: r.Environment, Tags: r.Tags, ResourceKind: r.Kind})
	}
	accounts, err := c.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accounts {
		k := Key("account", a.ID)
		g.AddNode(&Node{Key: k, Kind: "account", Label: a.System + ":" + a.Username, ID: a.ID, System: a.System,
			Status: a.Status, AccountKind: a.Kind, IdentityID: a.IdentityID})
		if a.IdentityID != nil {
			g.setEdge(Key("identity", *a.IdentityID), k, &Edge{Relation: "has_account", Source: "connector"})
		}
	}
	groups, err := c.Groups()
	if err != nil {
		return nil, err
	}
	for _, gr := range groups {
		g.AddNode(&Node{Key: Key("group", gr.ID), Kind: "group", Label: gr.System + ":" + gr.Name, Name: gr.Name,
			ID: gr.ID, System: gr.System, GroupKind: gr.Kind, Privileged: gr.Privileged, Requestable: gr.Requestable})
	}
	perms, err := c.Permissions()
	if err != nil {
		return nil, err
	}
	for _, p := range perms {
		res := g.nodes[Key("resource", p.ResourceID)]
		if res == nil {
			return nil, fmt.Errorf("graph: permission %d references missing resource %d", p.ID, p.ResourceID)
		}
		k := Key("perm", p.ID)
		g.AddNode(&Node{Key: k, Kind: "perm", Label: p.Action + " on " + res.Label, ID: p.ID, System: p.System,
			Action: p.Action, Privileged: p.Privileged, ResourceID: p.ResourceID, ResourceName: res.Label,
			Environment: res.Environment, Tags: res.Tags})
		g.setEdge(k, res.Key, &Edge{Relation: "on", Source: "connector"})
	}
	edges, err := c.Edges()
	if err != nil {
		return nil, err
	}
	for _, e := range edges {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			continue // expired JIT grants are not effective
		}
		if !g.HasNode(e.Src) || !g.HasNode(e.Dst) {
			continue
		}
		id := e.ID
		g.setEdge(e.Src, e.Dst, &Edge{Relation: e.Relation, EdgeID: &id, Source: e.Source, ExpiresAt: e.ExpiresAt})
	}
	return g, nil
}

// Copy returns an independent copy (nodes, edges and order).
func (g *Snapshot) Copy() *Snapshot {
	c := New()
	c.order = slices.Clone(g.order)
	for k, n := range g.nodes {
		nn := *n
		c.nodes[k] = &nn
	}
	for k, s := range g.succ {
		c.succ[k] = slices.Clone(s)
	}
	for k, e := range g.edges {
		ee := *e
		c.edges[k] = &ee
	}
	return c
}

// ------------------------------------------------------------- mutation

// RemoveEdge removes src -> dst and reports whether it existed.
func (g *Snapshot) RemoveEdge(src, dst string) bool {
	k := edgeKey{src, dst}
	if _, ok := g.edges[k]; !ok {
		return false
	}
	delete(g.edges, k)
	g.succ[src] = slices.DeleteFunc(g.succ[src], func(s string) bool { return s == dst })
	clear(g.eff)
	return true
}

// RemoveEdgeID removes the edge with a grant_edges id and returns its endpoints.
func (g *Snapshot) RemoveEdgeID(edgeID int64) (string, string, bool) {
	for _, src := range g.order {
		for _, dst := range g.succ[src] {
			if e := g.edges[edgeKey{src, dst}]; e.EdgeID != nil && *e.EdgeID == edgeID {
				g.RemoveEdge(src, dst)
				return src, dst, true
			}
		}
	}
	return "", "", false
}

// UnknownNodeError is returned when an edge references a node not in the graph.
type UnknownNodeError struct{ Msg string }

func (e *UnknownNodeError) Error() string { return e.Msg }

// AddEdge adds src -> dst (or updates it in place if present).
func (g *Snapshot) AddEdge(src, dst, relation, source string, expiresAt *time.Time) error {
	if !g.HasNode(src) || !g.HasNode(dst) {
		return &UnknownNodeError{fmt.Sprintf("unknown node in edge %s -> %s", src, dst)}
	}
	g.setEdge(src, dst, &Edge{Relation: relation, Source: source, ExpiresAt: expiresAt})
	clear(g.eff)
	return nil
}

// SetAccountStatus changes an account node's status.
func (g *Snapshot) SetAccountStatus(accountID int64, status string) error {
	n, ok := g.nodes[Key("account", accountID)]
	if !ok {
		return &UnknownNodeError{"'" + Key("account", accountID) + "'"}
	}
	n.Status = status
	clear(g.eff)
	return nil
}

// ---------------------------------------------------------------- query

// HasNode reports whether key is a node.
func (g *Snapshot) HasNode(key string) bool { _, ok := g.nodes[key]; return ok }

// Node returns the node for key (nil if absent).
func (g *Snapshot) Node(key string) *Node { return g.nodes[key] }

// Label returns a node's label (the key itself if unknown).
func (g *Snapshot) Label(key string) string {
	if n, ok := g.nodes[key]; ok {
		return n.Label
	}
	return key
}

// Nodes returns all nodes in insertion order.
func (g *Snapshot) Nodes() []*Node {
	out := make([]*Node, len(g.order))
	for i, k := range g.order {
		out[i] = g.nodes[k]
	}
	return out
}

// Successors returns the successors of key in insertion order.
func (g *Snapshot) Successors(key string) []string { return g.succ[key] }

// EdgeData returns the attributes of src -> dst (nil if absent).
func (g *Snapshot) EdgeData(src, dst string) *Edge { return g.edges[edgeKey{src, dst}] }

// Identities returns identity ids in node order.
func (g *Snapshot) Identities(includeTerminated bool) []int64 {
	var out []int64
	for _, k := range g.order {
		n := g.nodes[k]
		if n.Kind == "identity" && (includeTerminated || n.Status == "active") {
			out = append(out, n.ID)
		}
	}
	return out
}

func (g *Snapshot) traversable(key string) bool {
	n := g.nodes[key]
	return !(n.Kind == "account" && n.Status != "active")
}

type frame struct {
	cur  string
	path []string
}

// EffectivePermissions returns what an identity can do, with up to
// MaxPathsPerPermission paths per permission (shortest first).
func (g *Snapshot) EffectivePermissions(identityID int64) *Eff {
	if e, ok := g.eff[identityID]; ok {
		return e
	}
	result := &Eff{M: map[string]*EffectivePermission{}}
	start := Key("identity", identityID)
	if !g.HasNode(start) {
		return result
	}
	// iterative DFS enumerating simple paths that end on perm nodes
	stack := []frame{{start, []string{start}}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, nxt := range g.succ[f.cur] {
			if slices.Contains(f.path, nxt) {
				continue
			}
			nd := g.nodes[nxt]
			if nd.Kind == "resource" || !g.traversable(nxt) {
				continue
			}
			np := make([]string, len(f.path)+1)
			copy(np, f.path)
			np[len(f.path)] = nxt
			if nd.Kind == "perm" {
				ep, ok := result.M[nxt]
				if !ok {
					ep = &EffectivePermission{PermKey: nxt, PermID: nd.ID, Action: nd.Action, System: nd.System,
						Privileged: nd.Privileged, ResourceID: nd.ResourceID, ResourceName: nd.ResourceName,
						Environment: nd.Environment, Tags: slices.Clone(nd.Tags)}
					result.M[nxt] = ep
					result.Keys = append(result.Keys, nxt)
				}
				if len(ep.Paths) < MaxPathsPerPermission {
					ep.Paths = append(ep.Paths, np)
				}
				if !g.PathHasJIT(np) {
					ep.Standing = true
				}
				continue
			}
			stack = append(stack, frame{nxt, np})
		}
	}
	for _, ep := range result.M {
		sort.SliceStable(ep.Paths, func(i, j int) bool { return len(ep.Paths[i]) < len(ep.Paths[j]) })
	}
	g.eff[identityID] = result
	return result
}

// AllEffective computes effective permissions for every identity.
func (g *Snapshot) AllEffective() map[int64]*Eff {
	out := map[int64]*Eff{}
	for _, iid := range g.Identities(true) {
		out[iid] = g.EffectivePermissions(iid)
	}
	return out
}

// PathHasJIT reports whether any hop of the path is a JIT grant.
func (g *Snapshot) PathHasJIT(path []string) bool {
	for i := 1; i < len(path); i++ {
		if e := g.edges[edgeKey{path[i-1], path[i]}]; e != nil && e.Source == "jit" {
			return true
		}
	}
	return false
}

// FirstHopEdge is the grant edge leaving the account node (identity -> account -> X).
func FirstHopEdge(path []string) ([2]string, bool) {
	if len(path) >= 3 {
		return [2]string{path[1], path[2]}, true
	}
	return [2]string{}, false
}

// Via describes the edge a path step was reached through.
type Via struct {
	Relation  string  `json:"relation"`
	EdgeID    *int64  `json:"edge_id"`
	Source    string  `json:"source"`
	ExpiresAt *string `json:"expires_at"`
}

// PathStep is one step of a described path.
type PathStep struct {
	Key    string  `json:"key"`
	Kind   string  `json:"kind"`
	Label  string  `json:"label"`
	System *string `json:"system"`
	Via    *Via    `json:"via,omitempty"`
}

// DescribePath renders a path for the API.
func (g *Snapshot) DescribePath(path []string, iso func(*time.Time) *string) []PathStep {
	out := make([]PathStep, 0, len(path))
	for i, k := range path {
		d := g.nodes[k]
		step := PathStep{Key: k, Kind: d.Kind, Label: d.Label, System: optStr(d.System)}
		if i > 0 {
			ed := g.edges[edgeKey{path[i-1], k}]
			step.Via = &Via{Relation: ed.Relation, EdgeID: ed.EdgeID, Source: ed.Source, ExpiresAt: iso(ed.ExpiresAt)}
		}
		out = append(out, step)
	}
	return out
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// PathText renders "A → B → C".
func (g *Snapshot) PathText(path []string) string {
	labels := make([]string, len(path))
	for i, k := range path {
		labels[i] = g.Label(k)
	}
	return strings.Join(labels, " → ")
}

// WhoCanAccess maps identity id -> permissions on the resource, in identity order.
func (g *Snapshot) WhoCanAccess(resourceID int64) ([]int64, map[int64][]*EffectivePermission) {
	var ids []int64
	out := map[int64][]*EffectivePermission{}
	for _, iid := range g.Identities(true) {
		var hits []*EffectivePermission
		for _, ep := range g.EffectivePermissions(iid).Values() {
			if ep.ResourceID == resourceID {
				hits = append(hits, ep)
			}
		}
		if len(hits) > 0 {
			ids = append(ids, iid)
			out[iid] = hits
		}
	}
	return ids, out
}

// AccountGrant is an edge leaving one of an identity's accounts.
type AccountGrant struct {
	Acct, Dst string
	Edge      *Edge
}

// GrantEdgesFromAccounts lists edges account -> X for the identity's accounts.
func (g *Snapshot) GrantEdgesFromAccounts(identityID int64) []AccountGrant {
	start := Key("identity", identityID)
	var out []AccountGrant
	for _, acct := range g.succ[start] {
		for _, dst := range g.succ[acct] {
			out = append(out, AccountGrant{acct, dst, g.edges[edgeKey{acct, dst}]})
		}
	}
	return out
}

func pathHasEdge(path []string, edge [2]string) bool {
	for i := 1; i < len(path); i++ {
		if path[i-1] == edge[0] && path[i] == edge[1] {
			return true
		}
	}
	return false
}

// PermsLostIfRemoved returns permissions for which every known path traverses edge.
func PermsLostIfRemoved(eff *Eff, edge [2]string) []*EffectivePermission {
	var lost []*EffectivePermission
	for _, ep := range eff.Values() {
		all := true
		for _, p := range ep.Paths {
			if !pathHasEdge(p, edge) {
				all = false
				break
			}
		}
		if all {
			lost = append(lost, ep)
		}
	}
	return lost
}

// PermsViaEdge returns permissions with at least one path through edge.
func PermsViaEdge(eff *Eff, edge [2]string) []*EffectivePermission {
	var out []*EffectivePermission
	for _, ep := range eff.Values() {
		for _, p := range ep.Paths {
			if pathHasEdge(p, edge) {
				out = append(out, ep)
				break
			}
		}
	}
	return out
}

// Change lists permissions added and removed for one identity (sorted keys).
type Change struct {
	Added, Removed []string
}

// DiffEffective compares two effective-permission maps.
func DiffEffective(before, after map[int64]*Eff) map[int64]Change {
	changes := map[int64]Change{}
	ids := map[int64]bool{}
	for k := range before {
		ids[k] = true
	}
	for k := range after {
		ids[k] = true
	}
	for iid := range ids {
		b, a := before[iid], after[iid]
		var added, removed []string
		if a != nil {
			for _, k := range a.Keys {
				if b == nil || !b.Has(k) {
					added = append(added, k)
				}
			}
		}
		if b != nil {
			for _, k := range b.Keys {
				if a == nil || !a.Has(k) {
					removed = append(removed, k)
				}
			}
		}
		if len(added) > 0 || len(removed) > 0 {
			sort.Strings(added)
			sort.Strings(removed)
			changes[iid] = Change{Added: added, Removed: removed}
		}
	}
	return changes
}
