package rolesascode

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/cedarx"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
)

// The birthright fragment (design access-as-code-repo.md section 3.2): one permit policy per role,
//
//	@id("<key>-birthright") @role("<key>") [@abac("<attribute policy name>")]
//	permit (principal is Tessera::Identity, action == Tessera::Action::"birthright", resource == Tessera::Role::"<key>")
//	when { principal.status == "active" && principal has department && ["a", "b"].contains(principal.department)
//	       && ["human"].contains(principal.type) && principal has title && ["x"].contains(principal.title) };
//
// that is a conjunction of set-membership tests on department, type and title (roles.Rule's lists), with
// the status test that says the rule is for active identities. A residual condition over principal.attrs is
// an attribute policy (abac_policies) the rule names with @abac; the repository does not define it. Anything
// else (disjunction, unless, other attributes, entity references) is refused.

// ruleFields are the identity attributes a birthright rule tests, in the order they are written.
var ruleFields = []string{"department", "type", "title"}

// birthrightCedar writes the policy of a role's rule; abacName is the name of the attribute policy the
// rule names ("" none).
func birthrightCedar(key string, r *roles.Rule, abacName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "@id(%s)\n@role(%s)\n", cedarString(key+"-birthright"), cedarString(key))
	if abacName != "" {
		fmt.Fprintf(&b, "@abac(%s)\n", cedarString(abacName))
	}
	fmt.Fprintf(&b, "permit (principal is Tessera::Identity, action == Tessera::Action::\"birthright\",\n        resource == Tessera::Role::%s)\n", cedarString(key))
	conds := []string{`principal.status == "active"`}
	lists := map[string][]string{"department": r.Department, "type": r.Type, "title": r.Title}
	for _, f := range ruleFields {
		vs := lists[f]
		if len(vs) == 0 {
			continue
		}
		if f != "type" { // type is required on every identity; department and title are optional
			conds = append(conds, "principal has "+f)
		}
		q := make([]string, len(vs))
		for i, v := range vs {
			q[i] = cedarString(v)
		}
		conds = append(conds, "["+strings.Join(q, ", ")+"].contains(principal."+f+")")
	}
	b.WriteString("when { " + strings.Join(conds, "\n       && ") + " };\n")
	return b.String()
}

// cedarString is a Cedar string literal.
func cedarString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u{%x}`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ruleError is why a birthright policy is outside the fragment.
type ruleError struct{ msg string }

func (e *ruleError) Error() string { return e.msg }

func bad(format string, args ...any) error { return &ruleError{fmt.Sprintf(format, args...)} }

// compiledRule is a birthright policy read back: the lists and the name of the attribute policy.
type compiledRule struct {
	Rule     roles.Rule
	AbacName string
}

type node = map[string]any

// compileRule reads the policy with the given id of ps into a rule. role is the role key the file says
// it is for (@role); the scope must name the same role.
func compileRule(ps *cedarx.Policies, id, role string) (*compiledRule, error) {
	raw, err := ps.JSON(id)
	if err != nil {
		return nil, err
	}
	var pol struct {
		Principal  node   `json:"principal"`
		Action     node   `json:"action"`
		Resource   node   `json:"resource"`
		Conditions []node `json:"conditions"`
	}
	if err := json.Unmarshal(raw, &pol); err != nil {
		return nil, bad("the policy cannot be read: %v", err)
	}
	if op, _ := pol.Principal["op"].(string); op == "==" || op == "in" {
		return nil, bad("a birthright rule is for every identity: scope the principal with `principal is Tessera::Identity` or `principal`")
	}
	if !entityIs(pol.Action, "Tessera::Action", "birthright") {
		return nil, bad(`the action must be == Tessera::Action::"birthright"`)
	}
	if !entityIs(pol.Resource, "Tessera::Role", role) {
		return nil, bad(`the resource must be == Tessera::Role::%s (the role of @role)`, cedarString(role))
	}
	if len(pol.Conditions) != 1 {
		return nil, bad("a birthright rule has exactly one when clause")
	}
	if kind, _ := pol.Conditions[0]["kind"].(string); kind != "when" {
		return nil, bad("unless is not supported in a birthright rule")
	}
	var leaves []node
	if err := flatten(pol.Conditions[0]["body"], &leaves); err != nil {
		return nil, err
	}
	out := &compiledRule{}
	lists := map[string]*[]string{"department": &out.Rule.Department, "type": &out.Rule.Type, "title": &out.Rule.Title}
	seen := map[string]bool{}
	active := false
	for _, l := range leaves {
		switch {
		case l["has"] != nil:
			attr := attrOf(l["has"], "principal")
			if attr == "" || lists[attr] == nil {
				return nil, bad("`has` is supported on principal.department, principal.type and principal.title only")
			}
		case l["=="] != nil:
			left, right := operands(l["=="])
			attr := attrOf(left, "principal")
			val, ok := stringValue(right)
			switch {
			case attr == "status" && ok && val == "active":
				active = true
			case lists[attr] != nil && ok:
				if err := setList(seen, lists, attr, []string{val}); err != nil {
					return nil, err
				}
			default:
				return nil, bad("only principal.status == \"active\" and principal.<department|type|title> == \"value\" comparisons are supported")
			}
		case l["contains"] != nil:
			left, right := operands(l["contains"])
			attr := attrOf(right, "principal")
			vals, ok := stringSet(left)
			if lists[attr] == nil || !ok {
				return nil, bad("only [\"a\", \"b\"].contains(principal.<department|type|title>) is supported")
			}
			if err := setList(seen, lists, attr, vals); err != nil {
				return nil, err
			}
		default:
			return nil, bad("a birthright rule is a conjunction of set tests on principal.department, principal.type and principal.title; " +
				"use @abac(\"policy name\") for a condition on principal.attrs")
		}
	}
	if !active {
		return nil, bad(`a birthright rule must require principal.status == "active"`)
	}
	return out, nil
}

func setList(seen map[string]bool, lists map[string]*[]string, attr string, vals []string) error {
	if seen[attr] {
		return bad("principal.%s is tested twice", attr)
	}
	seen[attr] = true
	*lists[attr] = vals
	return nil
}

// flatten collects the operands of a chain of &&; any other operator is a leaf.
func flatten(body any, out *[]node) error {
	n, ok := body.(map[string]any)
	if !ok || len(n) != 1 {
		return bad("the condition cannot be read")
	}
	if and, ok := n["&&"]; ok {
		l, r := operands(and)
		if err := flatten(l, out); err != nil {
			return err
		}
		return flatten(r, out)
	}
	*out = append(*out, n)
	return nil
}

func operands(v any) (left, right any) {
	m, _ := v.(map[string]any)
	return m["left"], m["right"]
}

// attrOf is the attribute name of `<var>.attr` or `<var> has attr` ("" when it is not that).
func attrOf(v any, variable string) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if d, ok := m["."].(map[string]any); ok {
		m = d
	}
	if vr, ok := m["left"].(map[string]any); !ok || vr["Var"] != variable {
		return ""
	}
	a, _ := m["attr"].(string)
	return a
}

func stringValue(v any) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", false
	}
	s, ok := m["Value"].(string)
	return s, ok
}

func stringSet(v any) ([]string, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	elems, ok := m["Set"].([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(elems))
	for _, e := range elems {
		s, ok := stringValue(e)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, len(out) > 0
}

func entityIs(v node, typ, id string) bool {
	if op, _ := v["op"].(string); op != "==" {
		return false
	}
	e, _ := v["entity"].(map[string]any)
	return e != nil && e["type"] == typ && e["id"] == id
}

// sameRule says whether two rules (normalized, nil for none) are the same.
func sameRule(a, b *roles.Rule) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	}
	return slices.Equal(a.Department, b.Department) && slices.Equal(a.Type, b.Type) &&
		slices.Equal(a.Title, b.Title) && a.Policy == b.Policy
}
