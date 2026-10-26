package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/sod"
)

// TypeSoDRisk is the type of a policy that stands for one SoD risk (issue
// #298). It is never read from a file: Effective builds these from the
// tenant's rulesets, and the evaluator runs the risk through internal/sod, so
// what-if simulation, reviews and leaver plans see risks like any policy.
const TypeSoDRisk = "sod_risk"

// LegacyRulesetKey is the key of the ruleset the legacy YAML SoD policies are
// imported into.
const LegacyRulesetKey = "legacy-sod-policies"

func init() { Evaluators[TypeSoDRisk] = evalSoDRisk }

func toStrings(v any) []string {
	var out []string
	for _, x := range asList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// subjectsSpec is the spec form of a risk's subjects, as Context.subjects reads it.
func subjectsSpec(s *sod.Subjects) map[string]any {
	m := map[string]any{}
	if len(s.IdentityTypes) > 0 {
		m["identity_types"] = toAny(s.IdentityTypes)
	}
	if len(s.Statuses) > 0 {
		m["statuses"] = toAny(s.Statuses)
	}
	if s.Condition != nil {
		m["condition"] = s.Condition
	}
	return map[string]any{"subjects": m}
}

// SoD lists the violations of risks in the context's graph.
func (c *Context) SoD(risks []*sod.Risk) []sod.Violation {
	return sod.Detect(sod.Env{Graph: c.Graph, Subjects: func(s *sod.Subjects) []int64 { return c.subjects(subjectsSpec(s)) }}, risks)
}

// Policies returns one policy per risk.
func riskPolicies(risks []*sod.Risk) []*Policy {
	out := make([]*Policy, len(risks))
	for i, r := range risks {
		out[i] = &Policy{ID: r.Key, Name: r.Name, Type: TypeSoDRisk, Severity: r.Priority, Description: r.Description,
			Spec: map[string]any{"risk": r}, Enabled: true}
	}
	return out
}

// ToViolation is the policy-violation form of an SoD violation.
func ToViolation(v sod.Violation) Violation {
	id := v.IdentityID
	return Violation{PolicyID: v.RiskKey, PolicyName: v.RiskName, Severity: v.Priority, IdentityID: &id,
		IdentityName: v.IdentityName, Key: v.Key, Message: v.Message, Evidence: v.Evidence, Edges: v.Edges,
		ExplanationID: v.ExplanationID}
}

func evalSoDRisk(p *Policy, c *Context) ([]Violation, error) {
	r, ok := p.Spec["risk"].(*sod.Risk)
	if !ok {
		return nil, fmt.Errorf("policy %s: not a SoD risk", p.ID)
	}
	var out []Violation
	for _, v := range c.SoD([]*sod.Risk{r}) {
		out = append(out, ToViolation(v))
	}
	return out, nil
}

// Effective is the policies to evaluate: the file policies except the SoD
// ones, then one policy per SoD risk. The risks come from sod.Load, which
// falls back to LegacyBundle(file policies, false) for a tenant with no stored
// rulesets, so its detection results are those the YAML policies gave.
func Effective(files []*Policy, risks []*sod.Risk) []*Policy {
	out := make([]*Policy, 0, len(files)+len(risks))
	for _, p := range files {
		if p.Type != "separation_of_duties" {
			out = append(out, p)
		}
	}
	return append(out, riskPolicies(risks)...)
}

// LegacyBundle converts the enabled separation_of_duties file policies to a
// ruleset: each side of a policy's conflict becomes a function (equal sides are
// shared), each policy a risk keyed by the policy id, so violation keys and
// messages do not change. It returns nil when there are none. A policy that
// cannot be converted is an error when strict (an import), and skipped otherwise
// (the policy matched nothing before either).
func LegacyBundle(files []*Policy, strict bool) (*sod.Bundle, error) {
	b := &sod.Bundle{Schema: sod.SchemaTag, Ruleset: sod.RulesetDoc{Key: LegacyRulesetKey, Name: "Legacy SoD policies",
		Description: "Imported from the separation_of_duties YAML policies.", Enabled: true},
		Functions: []sod.FunctionDoc{}, Risks: []sod.RiskDoc{}}
	byName := map[string]string{} // function name -> key
	usedKeys := map[string]bool{}
	fn := func(actions []string) string {
		name := strings.Join(actions, ", ")
		if k, ok := byName[name]; ok {
			return k
		}
		base := sod.Slug(name)
		if base == "" {
			base = "function"
		}
		key := base
		for n := 2; usedKeys[key]; n++ {
			key = fmt.Sprintf("%s-%d", base, n)
		}
		usedKeys[key], byName[name] = true, key
		sels := make([]sod.Selector, len(actions))
		for i, a := range actions {
			sels[i] = sod.Selector{NamePattern: sod.EscapePattern(a)}
		}
		b.Functions = append(b.Functions, sod.FunctionDoc{Key: key, Name: name,
			Description: "Imported from a separation_of_duties policy.", Selectors: sels})
		return key
	}
	for _, p := range files {
		if p.Type != "separation_of_duties" || !p.Enabled {
			continue
		}
		conflict := mapOf(p.Spec["conflict"])
		a, c := toStrings(conflict["a"]), toStrings(conflict["b"])
		if len(a) == 0 || len(c) == 0 || len(a) != len(asList(conflict["a"])) || len(c) != len(asList(conflict["b"])) {
			if !strict {
				continue
			}
			return nil, fmt.Errorf("policy %s: conflict.a and conflict.b must be lists of action names", p.ID)
		}
		if !sod.ValidKey(p.ID) {
			if !strict {
				continue
			}
			return nil, fmt.Errorf("policy %q: the id is not a valid risk key", p.ID)
		}
		prio := p.Severity
		if _, ok := sod.PriorityRank[prio]; !ok {
			prio = "medium"
		}
		doc := sod.RiskDoc{Key: p.ID, Name: p.Name, Description: strings.TrimSpace(p.Description), Priority: prio,
			Functions: []string{fn(a), fn(c)}}
		if bp, ok := p.Spec["business_process"].(string); ok {
			doc.BusinessProcess = bp
		}
		subj := mapOf(p.Spec["subjects"])
		s := sod.Subjects{IdentityTypes: toStrings(subj["identity_types"]), Statuses: toStrings(subj["statuses"])}
		if cond, ok := subj["condition"]; ok {
			s.Condition = cond
		}
		if len(s.IdentityTypes) > 0 || len(s.Statuses) > 0 || s.Condition != nil {
			doc.Subjects = &s
		}
		b.Risks = append(b.Risks, doc)
	}
	if len(b.Risks) == 0 {
		return nil, nil
	}
	sort.Slice(b.Functions, func(i, j int) bool { return b.Functions[i].Key < b.Functions[j].Key })
	return b, nil
}
