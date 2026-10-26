package cedarx

import (
	"errors"
	"sort"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
)

// Policies is a parsed set of policies. Policy ids are cedar-go's: policy0,
// policy1, ... in file order.
type Policies struct {
	set *cedar.PolicySet
}

// Len is the number of policies.
func (p *Policies) Len() int { return len(p.set.Map()) }

// Set is the underlying cedar-go policy set, for the evaluator. Do not modify it.
func (p *Policies) Set() *cedar.PolicySet { return p.set }

// IDs are the policy ids in order.
func (p *Policies) IDs() []string {
	var ids []string
	for id := range p.set.All() {
		ids = append(ids, string(id))
	}
	sort.Slice(ids, func(i, j int) bool { return policyIndex(ids[i]) < policyIndex(ids[j]) })
	return ids
}

func policyIndex(id string) int {
	n := 0
	for i := len("policy"); i < len(id); i++ {
		n = n*10 + int(id[i]-'0')
	}
	return n
}

// ParsePolicies parses Cedar policies, refusing an oversized, too deeply nested
// or too complex source before the parser runs, and any annotation value over
// MaxAnnotationBytes. It does not check the policies against a schema; see
// Schema.Validate.
func ParsePolicies(name string, src []byte) (*Policies, error) {
	if err := Check(src, false); err != nil {
		return nil, err
	}
	ps, err := cedar.NewPolicySetFromBytes(name, src)
	if err != nil {
		return nil, errf(CodeSyntax, 0, "%v", err)
	}
	for id, p := range ps.All() {
		for k, v := range p.Annotations() {
			if len(v) > MaxAnnotationBytes {
				return nil, errf(CodeAnnotation, p.Position().Line, "%s: annotation @%s is %d bytes; at most %d", id, k, len(v), MaxAnnotationBytes)
			}
		}
	}
	return &Policies{set: ps}, nil
}

// Validate type-checks every policy against the schema (cedar-go's strict
// validator). All findings come back in one error, in policy order.
func (s *Schema) Validate(p *Policies) error {
	v := validate.New(s.resolved)
	var errs []error
	for _, id := range p.IDs() {
		pol := p.set.Get(cedar.PolicyID(id))
		if err := v.Policy(id, (*xast.Policy)(pol.AST())); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errf(CodeValidation, 0, "%v", errors.Join(errs...))
	}
	return nil
}

// ValidateEntities checks entities against the schema; at most MaxEntities.
func (s *Schema) ValidateEntities(es types.EntityMap) error {
	if len(es) > MaxEntities {
		return errf(CodeTooManyEntity, 0, "%d entities; at most %d", len(es), MaxEntities)
	}
	if err := validate.New(s.resolved).Entities(es); err != nil {
		return errf(CodeValidation, 0, "%v", err)
	}
	return nil
}

// Check parses src and validates it against the schema in one step.
func (s *Schema) Check(name string, src []byte) (*Policies, error) {
	p, err := ParsePolicies(name, src)
	if err != nil {
		return nil, err
	}
	if err := s.Validate(p); err != nil {
		return nil, err
	}
	return p, nil
}
