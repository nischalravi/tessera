package policygroups

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Compilation (design §8.3). A condition becomes a tree of union, intersection
// and complement (left minus right) over operands: groups, and attribute groups.
// Nodes are hash-consed: a node's identity is the hash of its canonical form
// (operands sorted for union and intersection, nested nodes of the same kind
// flattened, duplicates dropped), so identical subtrees of different policies are
// one node and, once applied, one internal group.
//
// Negation needs no universe group. A set is carried as a node and a sign: the
// node itself, or "everyone except the node". The algebra
//
//	A ∩ ¬B = A − B           ¬A ∩ ¬B = ¬(A ∪ B)
//	A ∪ ¬B = ¬(B − A)        ¬A ∪ ¬B = ¬(A ∩ B)
//
// closes over signed sets, and a condition whose result is still negated ("every
// identity except ...") cannot be listed and is refused (unbounded_negation).

// KindGroup is a node that stands for an existing group (a reference group, an
// exception group, another policy group). It is a leaf and has no internal group.
const KindGroup = "group"

// hashLen is the length of a node hash in hex digits.
const hashLen = 24

// Node is one node of compiled policy.
type Node struct {
	Hash  string
	Kind  string // KindGroup, or a store.Node* kind
	Attr  string // attr, has: the attribute, lower-cased
	Value string // attr: the value
	Group string // KindGroup: the group's id
	Name  string // KindGroup: the name as written, lower-cased
	Kids  []*Node
}

// IsLeaf reports whether the node has no operands.
func (n *Node) IsLeaf() bool { return len(n.Kids) == 0 }

// Eval evaluates the node over a membership oracle for its leaves (group, attr
// and has nodes). It is the set semantics of the tree, used by tests as the
// reference the engine must match.
func (n *Node) Eval(leaf func(*Node) bool) bool {
	switch n.Kind {
	case store.NodeEmpty:
		return false
	case store.NodeUnion:
		for _, k := range n.Kids {
			if k.Eval(leaf) {
				return true
			}
		}
		return false
	case store.NodeIntersection:
		for _, k := range n.Kids {
			if !k.Eval(leaf) {
				return false
			}
		}
		return true
	case store.NodeComplement:
		return n.Kids[0].Eval(leaf) && !n.Kids[1].Eval(leaf)
	}
	return leaf(n)
}

// Compiler interns nodes: use one for everything compiled in one apply.
type Compiler struct {
	nodes map[string]*Node
	empty *Node
}

// NewCompiler returns a compiler with no nodes yet.
func NewCompiler() *Compiler {
	c := &Compiler{nodes: map[string]*Node{}}
	c.empty = c.intern(&Node{Hash: EmptyHash, Kind: store.NodeEmpty})
	return c
}

// EmptyHash and EmptyHash2 are the hashes of the two empty groups. A policy
// group is complement(allow, deny) and the engine takes two distinct factors,
// so an empty side needs two different empty groups to stand for it.
const (
	EmptyHash  = "empty"
	EmptyHash2 = "empty2"
)

// Empty returns the empty node.
func (c *Compiler) Empty() *Node { return c.empty }

// Empty2 returns the second empty node (a distinct group with the same, empty, members).
func (c *Compiler) Empty2() *Node {
	return c.intern(&Node{Hash: EmptyHash2, Kind: store.NodeEmpty})
}

func (c *Compiler) intern(n *Node) *Node {
	if old, ok := c.nodes[n.Hash]; ok {
		return old
	}
	c.nodes[n.Hash] = n
	return n
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:hashLen]
}

// GroupRef returns the leaf for an existing group.
func (c *Compiler) GroupRef(id, name string) *Node {
	return c.intern(&Node{Hash: "g:" + id, Kind: KindGroup, Group: id, Name: strings.ToLower(name)})
}

// Attr returns the leaf for "identities whose attribute has the value".
func (c *Compiler) Attr(attr, value string) *Node {
	attr = strings.ToLower(attr)
	return c.intern(&Node{Hash: "a" + digest(fmt.Sprintf("a:%s:%d:%s", attr, len(value), value)), Kind: store.NodeAttr, Attr: attr, Value: value})
}

// Has returns the leaf for "identities that have the attribute".
func (c *Compiler) Has(attr string) *Node {
	attr = strings.ToLower(attr)
	return c.intern(&Node{Hash: "h" + digest("h:"+attr), Kind: store.NodeHas, Attr: attr})
}

var kindLetter = map[string]string{store.NodeUnion: "u", store.NodeIntersection: "i", store.NodeComplement: "c"}

func (c *Compiler) composite(kind string, kids []*Node) *Node {
	hs := make([]string, len(kids))
	for i, k := range kids {
		hs[i] = k.Hash
	}
	return c.intern(&Node{Hash: kindLetter[kind] + digest(kindLetter[kind]+"("+strings.Join(hs, ",")+")"), Kind: kind, Kids: kids})
}

// nary builds a union or intersection of kids (already flat, distinct, sorted
// and at least two), splitting a list longer than the engine's factor limit into
// a balanced tree of nodes of the same kind.
func (c *Compiler) nary(kind string, kids []*Node) *Node {
	for len(kids) > engine.MaxFactors {
		var next []*Node
		for i := 0; i < len(kids); i += engine.MaxFactors {
			end := min(i+engine.MaxFactors, len(kids))
			if end-i == 1 {
				next = append(next, kids[i])
			} else {
				next = append(next, c.composite(kind, slices.Clone(kids[i:end])))
			}
		}
		sortNodes(next)
		kids = next
	}
	return c.composite(kind, kids)
}

func sortNodes(ns []*Node) {
	slices.SortFunc(ns, func(a, b *Node) int { return strings.Compare(a.Hash, b.Hash) })
}

// flatten returns the operands of kind-nodes among ns, one level deep, dropping
// duplicates; the result is sorted by hash.
func flatten(kind string, ns []*Node) []*Node {
	seen := map[string]bool{}
	var out []*Node
	add := func(n *Node) {
		if !seen[n.Hash] {
			seen[n.Hash] = true
			out = append(out, n)
		}
	}
	for _, n := range ns {
		if n.Kind == kind && kind != store.NodeComplement {
			for _, k := range n.Kids {
				add(k)
			}
		} else {
			add(n)
		}
	}
	sortNodes(out)
	return out
}

// Union returns the union of nodes, simplified: the empty set drops out, one
// operand is itself, none is the empty set.
func (c *Compiler) Union(ns ...*Node) *Node {
	var live []*Node
	for _, n := range ns {
		if n.Kind != store.NodeEmpty {
			live = append(live, n)
		}
	}
	live = flatten(store.NodeUnion, live)
	switch len(live) {
	case 0:
		return c.empty
	case 1:
		return live[0]
	}
	return c.nary(store.NodeUnion, live)
}

// Inter returns the intersection of nodes, simplified: the empty set absorbs.
func (c *Compiler) Inter(ns ...*Node) *Node {
	for _, n := range ns {
		if n.Kind == store.NodeEmpty {
			return c.empty
		}
	}
	live := flatten(store.NodeIntersection, ns)
	switch len(live) {
	case 0:
		return c.empty
	case 1:
		return live[0]
	}
	return c.nary(store.NodeIntersection, live)
}

// Diff returns a minus b.
func (c *Compiler) Diff(a, b *Node) *Node {
	switch {
	case a.Kind == store.NodeEmpty || a.Hash == b.Hash:
		return c.empty
	case b.Kind == store.NodeEmpty:
		return a
	}
	return c.composite(store.NodeComplement, []*Node{a, b})
}

// sset is a set carried as a node and a sign: the node, or everyone but it.
type sset struct {
	n   *Node
	neg bool
}

// compiling is the state of compiling one file.
type compiling struct {
	c       *Compiler
	resolve func(name string) (id string, err error)
	diags   []Diagnostic
	path    string
	cache   map[string]*Node // lower-cased group name -> leaf
}

func (cc *compiling) group(g InGroup) *Node {
	k := strings.ToLower(g.Name)
	if n, ok := cc.cache[k]; ok {
		return n
	}
	id, err := cc.resolve(g.Name)
	if err != nil {
		cc.diags = append(cc.diags, Diagnostic{Path: cc.path, Line: g.At.Line, Col: g.At.Col, Code: CodeUnknownGroup, Msg: err.Error()})
		n := cc.c.GroupRef("unresolved:"+k, k)
		cc.cache[k] = n
		return n
	}
	n := cc.c.GroupRef(id, k)
	cc.cache[k] = n
	return n
}

func (cc *compiling) expr(x Expr) sset {
	c := cc.c
	switch n := x.(type) {
	case InGroup:
		return sset{n: cc.group(n)}
	case AttrEq:
		return sset{n: c.Attr(n.Attr, n.Value)}
	case AttrIn:
		ks := make([]*Node, len(n.Values))
		for i, v := range n.Values {
			ks[i] = c.Attr(n.Attr, v)
		}
		return sset{n: c.Union(ks...)}
	case AttrContains:
		return sset{n: c.Attr(n.Attr, n.Value)}
	case AttrHas:
		return sset{n: c.Has(n.Attr)}
	case Not:
		s := cc.expr(n.X)
		s.neg = !s.neg
		return s
	case And:
		return cc.and(operands(x, true))
	case Or:
		return cc.or(operands(x, false))
	}
	return sset{n: c.empty}
}

// operands flattens a chain of && (and) or || into its operands.
func operands(x Expr, and bool) []Expr {
	switch n := x.(type) {
	case And:
		if and {
			return append(operands(n.L, true), operands(n.R, true)...)
		}
	case Or:
		if !and {
			return append(operands(n.L, false), operands(n.R, false)...)
		}
	}
	return []Expr{x}
}

func (cc *compiling) split(ops []Expr) (pos, neg []*Node) {
	for _, op := range ops {
		s := cc.expr(op)
		if s.neg {
			neg = append(neg, s.n)
		} else {
			pos = append(pos, s.n)
		}
	}
	return pos, neg
}

func (cc *compiling) and(ops []Expr) sset {
	c := cc.c
	pos, neg := cc.split(ops)
	switch {
	case len(pos) == 0:
		return sset{n: c.Union(neg...), neg: true}
	case len(neg) == 0:
		return sset{n: c.Inter(pos...)}
	}
	return sset{n: c.Diff(c.Inter(pos...), c.Union(neg...))}
}

func (cc *compiling) or(ops []Expr) sset {
	c := cc.c
	pos, neg := cc.split(ops)
	if len(neg) == 0 {
		return sset{n: c.Union(pos...)}
	}
	n := c.Inter(neg...)
	if len(pos) > 0 {
		n = c.Diff(n, c.Union(pos...))
	}
	return sset{n: n, neg: true}
}

// Plan is a compiled policy file: the roots of its allow and deny sides.
type Plan struct {
	File  *File
	Allow *Node // the union of the permits; the empty node if there are none
	Deny  *Node // the union of the forbids; the empty node if there are none
}

// Digest is a stable identity of the compiled form: what the engine will hold.
func (p *Plan) Digest() string {
	return digest("allow=" + p.Allow.Hash + ";deny=" + p.Deny.Hash)
}

// Result is the node that equals the group's members: allow minus deny.
func (p *Plan) Result(c *Compiler) *Node { return c.Diff(p.Allow, p.Deny) }

// Compile compiles a validated file. resolve maps a group name to its id (the
// compiled form is keyed by id, so it survives a rename). It returns diagnostics
// for a group that does not resolve and for a condition that names "everyone
// except ..." with nothing to subtract from.
func (c *Compiler) Compile(f *File, resolve func(name string) (string, error)) (*Plan, []Diagnostic) {
	cc := &compiling{c: c, resolve: resolve, path: f.Path, cache: map[string]*Node{}}
	var permits, forbids []*Node
	for _, p := range f.Policies {
		s := cc.expr(p.Cond)
		if s.neg {
			cc.diags = append(cc.diags, Diagnostic{Path: f.Path, Line: p.At.Line, Col: p.At.Col, Code: CodeUnbounded,
				Msg: fmt.Sprintf("policy %q selects every identity except some: a group lists members, so add a positive condition (for example principal in Tessera::Group::\"...\") that it narrows", p.ID)})
			continue
		}
		if p.Effect == Permit {
			permits = append(permits, s.n)
		} else {
			forbids = append(forbids, s.n)
		}
	}
	if len(cc.diags) > 0 {
		return nil, cc.diags
	}
	return &Plan{File: f, Allow: c.Union(permits...), Deny: c.Union(forbids...)}, nil
}

// Reach returns every node of the plan below its roots, operands before the
// nodes that use them, without the group references.
func (p *Plan) Reach() []*Node {
	seen := map[string]bool{}
	var out []*Node
	var visit func(n *Node)
	visit = func(n *Node) {
		if seen[n.Hash] || n.Kind == KindGroup {
			return
		}
		seen[n.Hash] = true
		for _, k := range n.Kids {
			visit(k)
		}
		out = append(out, n)
	}
	visit(p.Allow)
	visit(p.Deny)
	return out
}

// GroupRefs returns the group ids the plan's nodes refer to.
func (p *Plan) GroupRefs() []string {
	seen := map[string]bool{}
	var out []string
	var visit func(n *Node)
	visit = func(n *Node) {
		if n.Kind == KindGroup {
			if !seen[n.Group] {
				seen[n.Group] = true
				out = append(out, n.Group)
			}
			return
		}
		for _, k := range n.Kids {
			visit(k)
		}
	}
	visit(p.Allow)
	visit(p.Deny)
	slices.Sort(out)
	return out
}
