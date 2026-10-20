package policygroups

import (
	"errors"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The attribute indexer (design §8.3-8.4). `principal.campus == "main"` compiles
// to the group sys:attr:campus:main, an ordinary basic group whose direct members
// carry source "attribute". The indexer keeps those memberships equal to the
// identities' attributes, only for the attribute and value pairs the compiled
// policy uses, so the number of groups stays bounded. Because the groups are
// ordinary, the engine needs no special case: it propagates an indexer change to
// every policy that uses the group.

// AttrSourceName is the source of the indexer's direct memberships.
const AttrSourceName = "attribute"

// AttrSource says what an identity's attributes are.
type AttrSource interface {
	// Values returns the identity's values of an attribute: one for a string
	// attribute, any number for a set, none when it has none. The attribute is
	// named as the schema does.
	Values(id *store.Identity, attr string) []string
}

// IdentityAttrs reads the attributes of the identity record: type, status,
// department, title and source. A data provider connector (design §8.4) is
// another AttrSource.
type IdentityAttrs struct{}

// Values implements AttrSource. A missing or empty field is no value.
func (IdentityAttrs) Values(id *store.Identity, attr string) []string {
	var v string
	switch strings.ToLower(attr) {
	case "type":
		v = id.Type
	case "status":
		v = id.Status
	case "department":
		v = deref(id.Department)
	case "title":
		v = deref(id.Title)
	case "source":
		v = deref(id.Source)
	}
	if v == "" {
		return nil
	}
	return []string{v}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// attrValues is the identity's values of an attribute, without empty strings and
// duplicates, as the evaluator and the indexer both read them.
func attrValues(src AttrSource, id *store.Identity, attr string) []string {
	var out []string
	for _, v := range src.Values(id, attr) {
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// memberOfAttr reports whether the identity belongs in the attribute group of a
// node: a string attribute counts when the identity has exactly that one value
// (the evaluator's reading of ==), a set attribute when it holds the value.
func memberOfAttr(schema Schema, vals []string, n *Node) bool {
	switch n.Kind {
	case store.NodeHas:
		return len(vals) > 0
	case store.NodeAttr:
		def := schema.Attrs[n.Attr]
		if def.Type == AttrSet {
			return slices.Contains(vals, n.Value)
		}
		return len(vals) == 1 && vals[0] == n.Value
	}
	return false
}

// attrDef finds the schema's definition of a lower-cased attribute name.
func (s Schema) attrDef(lower string) (name string, d AttrDef, ok bool) {
	for k, v := range s.Attrs {
		if strings.ToLower(k) == lower {
			return k, v, true
		}
	}
	return "", AttrDef{}, false
}

// IndexReport says what a reindex did.
type IndexReport struct {
	Groups  int  `json:"groups"`
	Added   int  `json:"added"`
	Removed int  `json:"removed"`
	Queued  bool `json:"queued"`
}

// Indexer keeps the attribute groups current.
type Indexer struct {
	Schema Schema
	Source AttrSource
}

func (ix Indexer) source() AttrSource {
	if ix.Source == nil {
		return IdentityAttrs{}
	}
	return ix.Source
}

// Reindex brings every attribute group of the tenant's compiled policy in line
// with the identities, in env's transaction. nodes limits it to some groups
// (nil: all).
func (ix Indexer) Reindex(env model.Env, nodes []*store.GrpPolicyNode) (*IndexReport, error) {
	if nodes == nil {
		for _, kind := range []string{store.NodeAttr, store.NodeHas} {
			ns, err := env.Tx.GrpPolicyNodes(kind)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, ns...)
		}
	}
	rep := &IndexReport{}
	if len(nodes) == 0 {
		return rep, nil
	}
	idents, err := env.Tx.Identities()
	if err != nil {
		return nil, err
	}
	src := ix.source()
	// the values of each identity, once per attribute used
	byAttr := map[string][][]string{}
	for _, n := range nodes {
		if _, done := byAttr[n.Attr]; done {
			continue
		}
		name, _, ok := ix.Schema.attrDef(n.Attr)
		vals := make([][]string, len(idents))
		if ok {
			for i, id := range idents {
				vals[i] = attrValues(src, id, name)
			}
		}
		byAttr[n.Attr] = vals
	}
	for _, n := range nodes {
		g, err := env.Tx.GrpGroup(n.GroupID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if g.Status == store.GroupDeleted {
			continue // retired: it is brought current when a policy uses it again
		}
		pn := &Node{Kind: n.Kind, Attr: n.Attr, Value: n.Value}
		var want []int64
		for i, id := range idents {
			if memberOfAttr(ix.Schema, byAttr[n.Attr][i], pn) {
				want = append(want, id.ID)
			}
		}
		res, err := env.SyncSourceMembers(g.ID, AttrSourceName, want)
		if err != nil {
			return nil, err
		}
		rep.Groups++
		rep.Added += res.Added
		rep.Removed += res.Removed
		rep.Queued = rep.Queued || res.Outcome.Queued
	}
	return rep, nil
}

// identitySubject is an identity as the evaluator sees it.
type identitySubject struct {
	id      *store.Identity
	src     AttrSource
	schema  Schema
	inGroup func(name string) (bool, error)
}

func (s identitySubject) InGroup(name string) (bool, error) { return s.inGroup(name) }

func (s identitySubject) Attr(name string) ([]string, bool) {
	vals := attrValues(s.src, s.id, name)
	return vals, len(vals) > 0
}
