package cedarx

import (
	"encoding/json"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
)

// ActionScope returns the actions the policy with the given id is scoped to
// (action == X, or action in [X, Y]). all is true when the scope names no
// action (a bare `action`, or `action in Group`), so the policy may apply to
// any fact shape. An unknown id is all.
func (p *Policies) ActionScope(id string) (actions []UID, all bool) {
	pol := p.set.Get(cedar.PolicyID(id))
	if pol == nil {
		return nil, true
	}
	switch s := (*xast.Policy)(pol.AST()).Action.(type) {
	case xast.ScopeTypeEq:
		return []UID{{Type: string(s.Entity.Type), ID: string(s.Entity.ID)}}, false
	case xast.ScopeTypeInSet:
		for _, e := range s.Entities {
			actions = append(actions, UID{Type: string(e.Type), ID: string(e.ID)})
		}
		return actions, false
	}
	return nil, true
}

// Only returns a set holding just the policy with the given id, or nil if
// there is none. The policy keeps its annotations; its id in the new set is policy0.
func (p *Policies) Only(id string) *Policies {
	pol := p.set.Get(cedar.PolicyID(id))
	if pol == nil {
		return nil
	}
	ps := cedar.NewPolicySet()
	ps.Add("policy0", pol)
	return &Policies{set: ps}
}

// Ref is an entity reference as an attribute value.
type Ref UID

// MarshalJSON writes Cedar's entity-reference JSON.
func (r Ref) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"__entity": map[string]string{"type": r.Type, "id": r.ID}})
}

// NewEntities returns an empty entity set.
func NewEntities() *Entities { return &Entities{m: types.EntityMap{}} }

// Add inserts an entity. attrs are JSON-encodable values (string, bool,
// integers, []string, []any, map[string]any, Ref); parents are the groups it
// is in. An entity with the same uid is replaced. The set is held to MaxEntities.
func (e *Entities) Add(uid UID, attrs map[string]any, parents ...UID) error {
	if attrs == nil {
		attrs = map[string]any{}
	}
	ps := make([]map[string]string, 0, len(parents))
	for _, p := range parents {
		ps = append(ps, map[string]string{"type": p.Type, "id": p.ID})
	}
	b, err := json.Marshal([]any{map[string]any{
		"uid":     map[string]string{"type": uid.Type, "id": uid.ID},
		"parents": ps,
		"attrs":   attrs,
	}})
	if err != nil {
		return errf(CodeSyntax, 0, "entity %s: %v", uid, err)
	}
	one, err := ParseEntities(b)
	if err != nil {
		return err
	}
	return e.Merge(one)
}
