package cedarx

import (
	"encoding/json"
	"fmt"
	"sort"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// UID is an entity reference such as Tessera::Identity::"alice".
type UID struct {
	Type string
	ID   string
}

func (u UID) cedar() types.EntityUID {
	return types.NewEntityUID(types.EntityType(u.Type), types.String(u.ID))
}

// String is the Cedar text form.
func (u UID) String() string { return u.cedar().String() }

// ParseUID reads the Cedar text form Type::"id".
func ParseUID(s string) (UID, error) {
	if len(s) > 1024 {
		return UID{}, errf(CodeSyntax, 0, "entity reference is %d bytes", len(s))
	}
	var e types.EntityUID
	if err := e.UnmarshalCedar([]byte(s)); err != nil {
		return UID{}, errf(CodeSyntax, 0, "entity reference %q is not of the form Type::\"id\"", s)
	}
	return UID{Type: string(e.Type), ID: string(e.ID)}, nil
}

// Entities is a set of entities, as the evaluator reads them.
type Entities struct {
	m types.EntityMap
}

// MaxEntityBytes bounds the JSON of one entity set.
const MaxEntityBytes = 16 * MaxFileBytes

// ParseEntities reads a JSON array of entities in Cedar's entity JSON format
// (uid, parents, attrs), at most MaxEntities and MaxEntityBytes.
func ParseEntities(src []byte) (*Entities, error) {
	if len(src) > MaxEntityBytes {
		return nil, errf(CodeTooLarge, 0, "%d bytes; entities are at most %d", len(src), MaxEntityBytes)
	}
	var m types.EntityMap
	if err := json.Unmarshal(src, &m); err != nil {
		return nil, errf(CodeSyntax, 0, "entities: %v", err)
	}
	if len(m) > MaxEntities {
		return nil, errf(CodeTooManyEntity, 0, "%d entities; at most %d", len(m), MaxEntities)
	}
	return &Entities{m: m}, nil
}

// Len is the number of entities.
func (e *Entities) Len() int { return len(e.m) }

// Merge adds the entities of o; on the same uid, o's wins. The total is held to MaxEntities.
func (e *Entities) Merge(o *Entities) error {
	if e.m == nil {
		e.m = types.EntityMap{}
	}
	for k, v := range o.m {
		e.m[k] = v
	}
	if len(e.m) > MaxEntities {
		return errf(CodeTooManyEntity, 0, "%d entities; at most %d", len(e.m), MaxEntities)
	}
	return nil
}

// ValidateSet checks the entities against the schema.
func (s *Schema) ValidateSet(e *Entities) error { return s.ValidateEntities(e.m) }

// Request is one authorization question. Context is a JSON object, or empty.
type Request struct {
	Principal, Action, Resource UID
	Context                     []byte
}

// Reason is a policy that decided: its id in the set, its @id annotation if any, and its line.
type Reason struct {
	Policy string
	ID     string
	Line   int
}

// Decision is cedar's answer: Allow, with the permits that allowed or the forbids
// that denied (Reasons), and the policies that errored at evaluation (Errors).
type Decision struct {
	Allow   bool
	Reasons []Reason
	Errors  []string
}

// Decide evaluates the request against the union of the policy sets: any
// satisfied forbid denies; otherwise any satisfied permit allows; otherwise deny.
func Decide(e *Entities, req Request, sets ...*Policies) (Decision, error) {
	var ctx types.Record
	if len(req.Context) > 0 {
		if len(req.Context) > MaxFileBytes {
			return Decision{}, errf(CodeTooLarge, 0, "context is %d bytes", len(req.Context))
		}
		if err := json.Unmarshal(req.Context, &ctx); err != nil {
			return Decision{}, errf(CodeSyntax, 0, "context: %v", err)
		}
	}
	all := cedar.NewPolicySet()
	for i, ps := range sets {
		for _, id := range ps.IDs() {
			all.Add(cedar.PolicyID(fmt.Sprintf("%d/%s", i, id)), ps.set.Get(cedar.PolicyID(id)))
		}
	}
	var ents types.EntityGetter
	if e != nil {
		ents = e.m
	}
	d, diag := cedar.Authorize(all, ents, cedar.Request{
		Principal: req.Principal.cedar(), Action: req.Action.cedar(), Resource: req.Resource.cedar(), Context: ctx,
	})
	out := Decision{Allow: d == cedar.Allow}
	for _, r := range diag.Reasons {
		id := ""
		if p := all.Get(r.PolicyID); p != nil {
			id = string(p.Annotations()["id"])
		}
		out.Reasons = append(out.Reasons, Reason{Policy: string(r.PolicyID), ID: id, Line: r.Position.Line})
	}
	sort.Slice(out.Reasons, func(i, j int) bool { return out.Reasons[i].Policy < out.Reasons[j].Policy })
	for _, er := range diag.Errors {
		out.Errors = append(out.Errors, fmt.Sprintf("%s: %s", er.PolicyID, er.Message))
	}
	return out, nil
}

// Annotation returns the value of the annotation @name on the policy with the
// given id (as in IDs), and whether it has one.
func (p *Policies) Annotation(id, name string) (string, bool) {
	pol := p.set.Get(cedar.PolicyID(id))
	if pol == nil {
		return "", false
	}
	v, ok := pol.Annotations()[types.Ident(name)]
	return string(v), ok
}

// Effect is "permit" or "forbid" for the policy with the given id.
func (p *Policies) Effect(id string) string {
	pol := p.set.Get(cedar.PolicyID(id))
	if pol == nil {
		return ""
	}
	if pol.Effect() == cedar.Forbid {
		return "forbid"
	}
	return "permit"
}

// Line is the 1-based line of the policy, or 0.
func (p *Policies) Line(id string) int {
	if pol := p.set.Get(cedar.PolicyID(id)); pol != nil {
		return pol.Position().Line
	}
	return 0
}
