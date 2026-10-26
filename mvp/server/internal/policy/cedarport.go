package policy

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/mfa"
)

// ErrNotPortable is returned by ToCedar for a YAML policy that Cedar cannot
// state with the same findings; it stays YAML (the fallback).
var ErrNotPortable = errors.New("policy: not portable to Cedar")

func notPortable(p *Policy, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrNotPortable, p.ID, fmt.Sprintf(format, args...))
}

// ToCedar writes the Cedar invariant of a YAML policy (design section 3.6): the
// annotations carry the policy fields and a forbid over one fact shape carries
// its rule. Evaluated with Evaluate it gives the same violations as the YAML
// (TestCedarPortMatchesYAML). Not ported: separation_of_duties (a SoD risk,
// internal/sod), a subjects.condition (an attribute condition of internal/abac),
// and a spec of an unexpected shape (a scalar where a list is read, a
// fractional secret age, a description over the annotation limit).
func ToCedar(p *Policy) (string, error) {
	var action, when string
	var err error
	extra := map[string]string{}
	switch p.Type {
	case "forbidden_access":
		action = FactReach
		when, err = joinWhen(portSubjects(p), portPerm(p, mapOf(p.Spec["resources"])))
	case "no_standing_access":
		action = FactReach
		when, err = joinWhen(portSubjects(p), portPerm(p, mapOf(p.Spec["match"])), "context.standing", nil)
	case "terminated_with_access":
		action = FactReach
		when = `principal.status == "terminated"`
	case "secret_max_age":
		action = FactHoldCredential
		when, err = portSecretAge(p, extra)
	case "nhi_ownership":
		action = FactExist
		when = `["service", "ai_agent"].contains(principal.type) && principal.status == "active" && ` +
			`!(principal has owner && principal.owner.status == "active")`
	case "mfa_required":
		action = FactExist
		when, err = portMFA(p, extra)
	case "separation_of_duties":
		return "", notPortable(p, "separation of duties is a SoD risk; policy.LegacyBundle converts it")
	default:
		return "", notPortable(p, "unknown type %q", p.Type)
	}
	if err != nil {
		return "", err
	}
	if usesSubjects(p.Type) && mapOf(p.Spec["subjects"])["condition"] != nil {
		return "", notPortable(p, "subjects.condition is not expressible over facts")
	}
	var b strings.Builder
	ann := func(k, v string) { fmt.Fprintf(&b, "@%s(%s)\n", k, cedarString(v)) }
	ann("id", p.ID)
	ann("name", p.Name)
	ann("severity", p.Severity)
	if p.Description != "" {
		ann("description", p.Description)
	}
	ann("type", p.Type)
	if !p.Enabled {
		ann("enabled", "false")
	}
	for _, k := range []string{"max_age_days", "require"} {
		if v, ok := extra[k]; ok {
			ann(k, v)
		}
	}
	fmt.Fprintf(&b, "forbid (principal, action == %s::%s, resource)\nwhen { %s };\n", typeAction, cedarString(action), when)
	out := b.String()
	if _, err := ParseInvariants(p.ID, []byte(out)); err != nil {
		return "", notPortable(p, "%v", err)
	}
	return out, nil
}

func usesSubjects(typ string) bool {
	return typ == "forbidden_access" || typ == "no_standing_access" || typ == "mfa_required"
}

// joinWhen joins the parts with &&, in parentheses; a part is an expression or
// an error already found. It takes (expr, err) pairs flattened by the callers.
func joinWhen(parts ...any) (string, error) {
	var exprs []string
	for i := 0; i < len(parts); i++ {
		switch x := parts[i].(type) {
		case string:
			exprs = append(exprs, x)
		case error:
			return "", x
		case nil:
		}
	}
	out := make([]string, 0, len(exprs))
	for _, e := range exprs {
		if e != "" {
			out = append(out, "("+e+")")
		}
	}
	if len(out) == 0 {
		return "true", nil
	}
	return strings.Join(out, " && "), nil
}

// portSubjects is the subjects: filter of a policy as a Cedar condition (the
// subjects() of the YAML engine without its attribute condition).
func portSubjects(p *Policy) any {
	subj := mapOf(p.Spec["subjects"])
	var parts []string
	if raw := asList(subj["identity_types"]); len(raw) > 0 {
		parts = append(parts, inList("principal.type", raw))
	}
	statuses := []any{"active"}
	if v, ok := subj["statuses"]; ok {
		statuses = asList(v)
	}
	parts = append(parts, inList("principal.status", statuses))
	return strings.Join(parts, " && ")
}

// inList is `expr is one of the strings of raw`; non-strings never match.
func inList(expr string, raw []any) string {
	var lits []string
	for _, v := range raw {
		if s, ok := v.(string); ok {
			lits = append(lits, cedarString(s))
		}
	}
	switch len(lits) {
	case 0:
		return "false"
	case 1:
		return expr + " == " + lits[0]
	}
	return "[" + strings.Join(lits, ", ") + "].contains(" + expr + ")"
}

// portPerm is permMatches over the fact: the resource and context attributes.
func portPerm(p *Policy, m map[string]any) any {
	var parts []string
	list := func(key, expr string) error {
		v, ok := m[key]
		if !ok {
			return nil
		}
		raw, isList := v.([]any)
		if !isList {
			return notPortable(p, "%s is not a list", key)
		}
		parts = append(parts, inList(expr, raw))
		return nil
	}
	if err := list("actions", "context.action"); err != nil {
		return err
	}
	if v, ok := m["privileged"]; ok {
		switch x := v.(type) {
		case bool:
			parts = append(parts, fmt.Sprintf("resource.privileged == %t", x))
		case int:
			if x == 0 || x == 1 {
				parts = append(parts, fmt.Sprintf("resource.privileged == %t", x == 1))
			} else {
				parts = append(parts, "false")
			}
		default:
			parts = append(parts, "false")
		}
	}
	if v, ok := m["environment"]; ok {
		switch x := v.(type) {
		case nil:
			parts = append(parts, "!(resource has environment)")
		case string:
			parts = append(parts, "(resource has environment && resource.environment == "+cedarString(x)+")")
		default:
			parts = append(parts, "false")
		}
	}
	if err := list("systems", "context.system"); err != nil {
		return err
	}
	if v, ok := m["tags_any"]; ok {
		raw, isList := v.([]any)
		if !isList {
			return notPortable(p, "tags_any is not a list")
		}
		var lits []string
		for _, t := range raw {
			if s, ok := t.(string); ok {
				lits = append(lits, cedarString(s))
			}
		}
		if len(lits) == 0 {
			parts = append(parts, "false")
		} else {
			parts = append(parts, "resource.tags.containsAny(["+strings.Join(lits, ", ")+"])")
		}
	}
	return strings.Join(parts, " && ")
}

func portSecretAge(p *Policy, extra map[string]string) (string, error) {
	maxAge := any(90)
	if v, ok := p.Spec["max_age_days"]; ok {
		maxAge = v
	}
	limit, ok := toFloat(maxAge)
	if !ok || math.IsNaN(limit) || math.IsInf(limit, 0) || math.Abs(limit) > 1e9 {
		return "", notPortable(p, "max_age_days must be a number")
	}
	extra["max_age_days"] = fmt.Sprint(maxAge)
	// ages are whole days: age > limit is age > floor(limit)
	return fmt.Sprintf(`resource.age_days > %d && principal.status == "active"`, int64(math.Floor(limit))), nil
}

func portMFA(p *Policy, extra map[string]string) (string, error) {
	required := mfa.PhishingResistant
	if v, ok := p.Spec["require"]; ok {
		required = mfa.Strength(fmt.Sprint(v))
		if !required.Valid() {
			return "", notPortable(p, "require must be one of %v", mfa.Strengths)
		}
	}
	extra["require"] = string(required)
	weak := []string{cedarString(string(mfa.None))}
	for _, s := range mfa.Strengths {
		if s.Rank() < required.Rank() {
			weak = append(weak, cedarString(string(s)))
		}
	}
	rule := `principal in ` + typeGroup + `::"privileged" && principal has mfa_strength && [` +
		strings.Join(weak, ", ") + `].contains(principal.mfa_strength)`
	subj, err := joinWhen(portSubjects(p), rule)
	return subj, err
}

// cedarString is a Cedar string literal. Control characters are written as
// \u{..} escapes; everything else is kept as is.
func cedarString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f || r == 0xfffd:
			fmt.Fprintf(&b, `\u{%x}`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
