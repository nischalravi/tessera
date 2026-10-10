package policy

import (
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

// Serialize writes the canonical JSON form of a parsed document: compact, no
// HTML escaping, elements in a fixed order (Version, Id, Statement; Sid,
// Effect, Principal, NotPrincipal, Action, NotAction, Resource, NotResource,
// Condition), every string-or-list element as a list, the Statement element
// as a list, condition keys lower-cased and operators in canonical spelling.
// Dropped statements are not written.
//
// Serialize is a normal form, not a copy of the input: RawJSON keeps the
// exact bytes. Parsing the output gives the same statements, so
// Serialize(Parse(Serialize(Parse(x)))) == Serialize(Parse(x)).
func Serialize(doc *model.PolicyDoc) ([]byte, error) {
	root := ojson.Object{}
	if doc.LanguageVersion != "" {
		root = append(root, ojson.KV{Key: "Version", Value: doc.LanguageVersion})
	}
	if doc.IDElement != "" {
		root = append(root, ojson.KV{Key: "Id", Value: doc.IDElement})
	}
	stmts := make([]any, 0, len(doc.Statements))
	for i := range doc.Statements {
		s, err := serializeStatement(&doc.Statements[i])
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, s)
	}
	root = append(root, ojson.KV{Key: "Statement", Value: stmts})
	return ojson.Marshal(root)
}

func serializeStatement(st *model.Statement) (ojson.Object, error) {
	o := ojson.Object{}
	if st.Sid != "" {
		o = append(o, ojson.KV{Key: "Sid", Value: st.Sid})
	}
	eff := st.Effect.PolicyElement()
	if eff == "" {
		return nil, fmt.Errorf("policy: statement %d has no effect", st.Index)
	}
	o = append(o, ojson.KV{Key: "Effect", Value: eff})
	if st.Principals != nil {
		o = append(o, ojson.KV{Key: "Principal", Value: serializePrincipal(st.Principals)})
	}
	if st.NotPrincipals != nil {
		o = append(o, ojson.KV{Key: "NotPrincipal", Value: serializePrincipal(st.NotPrincipals)})
	}
	for _, e := range []struct {
		key string
		ps  *model.PatternSet
	}{{"Action", st.Actions}, {"NotAction", st.NotActions}, {"Resource", st.Resources}, {"NotResource", st.NotResources}} {
		if e.ps != nil {
			o = append(o, ojson.KV{Key: e.key, Value: nonNil(e.ps.Patterns)})
		}
	}
	if st.Condition != nil {
		// Regroup the atoms into operator blocks, keeping first-appearance order.
		cond := ojson.Object{}
		index := map[string]int{}
		for _, a := range st.Condition {
			name := OperatorName(a)
			i, ok := index[name]
			if !ok {
				i = len(cond)
				index[name] = i
				cond = append(cond, ojson.KV{Key: name, Value: ojson.Object{}})
			}
			block := cond[i].Value.(ojson.Object)
			cond[i].Value = append(block, ojson.KV{Key: a.Key, Value: nonNil(a.Values)})
		}
		o = append(o, ojson.KV{Key: "Condition", Value: cond})
	}
	return o, nil
}

func serializePrincipal(ps *model.PrincipalSet) any {
	if ps.Star {
		return "*"
	}
	o := ojson.Object{}
	for _, e := range []struct {
		key  string
		vals []string
	}{{"AWS", ps.AWS}, {"CanonicalUser", ps.CanonicalUser}, {"Federated", ps.Federated}, {"Service", ps.Service}} {
		if e.vals != nil {
			o = append(o, ojson.KV{Key: e.key, Value: e.vals})
		}
	}
	return o
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
