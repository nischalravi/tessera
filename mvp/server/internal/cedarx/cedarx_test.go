package cedarx

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func TestCheck_Limits(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("(", n) + "1" + strings.Repeat(")", n) }
	cases := []struct {
		name, src, want string
		schema          bool
	}{
		{"empty", ``, "", false},
		{"ok", `permit (principal, action, resource);`, "", false},
		{"depth at the limit", `permit (principal, action, resource) when { ` + deep(MaxDepth-1) + ` };`, "", false},
		{"depth over the limit", `permit (principal, action, resource) when { ` + deep(MaxDepth) + ` };`, CodeTooDeep, false},
		{"huge depth", strings.Repeat("(", 1<<16), CodeTooDeep, false},
		{"unclosed brackets", strings.Repeat("[", 100), CodeTooDeep, false},
		{"brackets in a string", `permit (principal, action, resource) when { "` + strings.Repeat("(", 500) + `" == "x" };`, "", false},
		{"brackets in a comment", "// " + strings.Repeat("{", 500) + "\n", "", false},
		{"escaped quote in a string", `"\"` + strings.Repeat("(", 500) + `"`, "", false},
		{"chained not", `permit (principal, action, resource) when { ` + strings.Repeat("!", MaxDepth+1) + `true };`, CodeTooDeep, false},
		{"chained negation", `when { ` + strings.Repeat("-", 100) + `1 }`, CodeTooDeep, false},
		{"nested ifs", strings.Repeat("if a then ", MaxDepth+1), CodeTooDeep, false},
		{"ifs across policies reset", strings.Repeat("permit (principal, action, resource) when { if true then true else false };\n", 100), "", false},
		{"schema generics", `entity A { a: ` + strings.Repeat("Set<", MaxDepth+1) + `String` + strings.Repeat(">", MaxDepth+1) + ` };`, CodeTooDeep, true},
		{"generics are not brackets in a policy", `when { a < ` + strings.Repeat("<", 200) + ` }`, "", false},
		{"too many tokens", `when { ` + strings.Repeat("a && ", MaxPolicyTokens) + `a }`, CodeTooComplex, false},
		{"oversized", strings.Repeat(" ", MaxFileBytes+1), CodeTooLarge, false},
		{"at the size limit", strings.Repeat(" ", MaxFileBytes), "", false},
		{"too many policies", strings.Repeat(";", MaxPolicies+1), CodeTooComplex, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := code(Check([]byte(c.src), c.schema)); got != c.want {
				t.Errorf("code = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCheck_ReportsTheLine(t *testing.T) {
	err := Check([]byte("\n\n"+strings.Repeat("(", MaxDepth+1)), false)
	var e *Error
	if !errors.As(err, &e) || e.Line != 3 {
		t.Fatalf("err = %v", err)
	}
}

// TestParse_RefusesBeforeParsing: a source over a limit never reaches cedar-go;
// a deeply nested one would otherwise recurse as deep as it is long.
func TestParse_RefusesBeforeParsing(t *testing.T) {
	src := `permit (principal, action, resource) when { ` + strings.Repeat("(", 300000) + `};`
	if got := code(func() error { _, err := ParsePolicies("p.cedar", []byte(src)); return err }()); got != CodeTooLarge {
		t.Errorf("code = %q, want %q", got, CodeTooLarge)
	}
	src = `permit (principal, action, resource) when { ` + strings.Repeat("(", 5000) + `};`
	if got := code(func() error { _, err := ParsePolicies("p.cedar", []byte(src)); return err }()); got != CodeTooDeep {
		t.Errorf("code = %q, want %q", got, CodeTooDeep)
	}
	if got := code(func() error { _, err := ParseSchema("s", []byte(strings.Repeat("{", 5000))); return err }()); got != CodeTooDeep {
		t.Errorf("schema code = %q, want %q", got, CodeTooDeep)
	}
}

func TestParsePolicies(t *testing.T) {
	long := strings.Repeat("x", MaxAnnotationBytes+1)
	cases := []struct {
		name, src, want string
		n               int
	}{
		{"two policies", "permit (principal, action, resource);\nforbid (principal, action, resource);", "", 2},
		{"annotations", `@id("a") @severity("high") permit (principal, action, resource);`, "", 1},
		{"annotation at the limit", `@m("` + long[1:] + `") permit (principal, action, resource);`, "", 1},
		{"annotation too long", `@m("` + long + `") permit (principal, action, resource);`, CodeAnnotation, 0},
		{"syntax", `permit (principal, action;`, CodeSyntax, 0},
		{"not cedar", `{"a": 1}`, CodeSyntax, 0},
		{"nul bytes", "permit\x00(principal);", CodeSyntax, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps, err := ParsePolicies("p.cedar", []byte(c.src))
			if got := code(err); got != c.want {
				t.Fatalf("code = %q (%v), want %q", got, err, c.want)
			}
			if err == nil && ps.Len() != c.n {
				t.Errorf("%d policies, want %d", ps.Len(), c.n)
			}
		})
	}
}

func TestPolicies_IDsInOrder(t *testing.T) {
	ps, err := ParsePolicies("p", []byte(strings.Repeat("permit (principal, action, resource);\n", 12)))
	if err != nil {
		t.Fatal(err)
	}
	ids := ps.IDs()
	if len(ids) != 12 || ids[2] != "policy2" || ids[10] != "policy10" {
		t.Errorf("ids = %v", ids)
	}
}

func TestGenerate_SchemaIsValidAndStable(t *testing.T) {
	a, err := Generate(Facts{IdentityAttrs: []string{"cost_center", "region", "cost_center"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(Facts{IdentityAttrs: []string{"region", "cost_center"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Text(), b.Text()) {
		t.Error("the schema depends on the order or repetition of the attributes")
	}
	if !strings.Contains(string(a.Text()), "cost_center?: String") {
		t.Errorf("no attribute in:\n%s", a.Text())
	}
	if _, err := Generate(Facts{}); err != nil {
		t.Errorf("no attributes: %v", err)
	}
	// the generated text parses back to a schema
	if _, err := ParseSchema("again", a.Text()); err != nil {
		t.Errorf("round trip: %v", err)
	}
}

func TestGenerate_RefusesBadAttributeNames(t *testing.T) {
	for _, bad := range []string{"", "a b", "a-b", "1a", "a}; entity X {", `a"`, "permit", "principal", strings.Repeat("a", 65), "é"} {
		if _, err := Generate(Facts{IdentityAttrs: []string{bad}}); code(err) != CodeSchema {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	many := make([]string, MaxEntities+1)
	if _, err := Generate(Facts{IdentityAttrs: many}); code(err) != CodeTooComplex {
		t.Errorf("many attributes: %v", err)
	}
}

func TestSchemaValidate(t *testing.T) {
	s, err := Generate(Facts{IdentityAttrs: []string{"cost_center"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, src string
		ok        bool
	}{
		{"birthright", `@id("pa") permit (principal is Tessera::Identity, action == Tessera::Action::"birthright", resource == Tessera::Role::"pa")
			when { principal.status == "active" && ["finance"].contains(principal.department) };`, false}, // department is optional: unguarded
		{"birthright guarded", `permit (principal is Tessera::Identity, action == Tessera::Action::"birthright", resource == Tessera::Role::"pa")
			when { principal.status == "active" && principal has department && principal.department == "finance" && principal.attrs has cost_center && principal.attrs.cost_center == "4410" };`, true},
		{"invariant", `forbid (principal, action == Tessera::Action::"reach", resource)
			when { principal.type == "human" && resource.privileged && resource.environment == "prod" };`, false}, // environment optional
		{"invariant guarded", `forbid (principal, action == Tessera::Action::"reach", resource)
			when { principal.type == "human" && resource.privileged && resource has environment && resource.environment == "prod" && context.standing && !context.via_jit };`, true},
		{"credential", `forbid (principal, action == Tessera::Action::"hold_credential", resource) when { resource.age_days > 90 };`, true},
		{"design 3.6 forbidden_access", `forbid (principal, action == Tessera::Action::"reach", resource) when { principal.type == "ai_agent" && resource.tags.contains("pii") };`, true},
		{"design 3.6 terminated_with_access", `forbid (principal, action == Tessera::Action::"reach", resource) when { principal.status == "terminated" };`, true},
		{"design 3.6 nhi_ownership", `forbid (principal, action == Tessera::Action::"exist", resource) when { ["service","ai_agent"].contains(principal.type) && principal.status == "active" && !(principal has owner && principal.owner.status == "active") };`, true},
		{"design 3.6 mfa_required", `forbid (principal, action == Tessera::Action::"exist", resource) when { principal.type == "human" && !(principal has mfa_strength && principal.mfa_strength == "phishing_resistant") };`, true},
		{"agent scope", `permit (principal == Tessera::Agent::"entra:7f3c", action == Tessera::Action::"reach", resource) when { ["list","read"].contains(context.action_class) && resource.tags.contains("support") && context.system == "aws" };`, true},
		{"unknown action", `forbid (principal, action == Tessera::Action::"nope", resource);`, false},
		{"wrong type", `forbid (principal, action == Tessera::Action::"hold_credential", resource) when { resource.age_days == "x" };`, false},
		{"unknown attribute", `forbid (principal, action == Tessera::Action::"exist", resource) when { principal.shoe == "x" };`, false},
		{"unknown attr key", `forbid (principal, action == Tessera::Action::"exist", resource) when { principal.attrs has nope && principal.attrs.nope == "x" };`, true}, // has on a record attr is allowed
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.Check("p.cedar", []byte(c.src))
			if (err == nil) != c.ok {
				t.Errorf("err = %v, want ok = %v", err, c.ok)
			} else if err != nil && code(err) != CodeValidation {
				t.Errorf("code = %q", code(err))
			}
		})
	}
}

func TestValidateEntities(t *testing.T) {
	s, err := Generate(Facts{})
	if err != nil {
		t.Fatal(err)
	}
	uid := types.NewEntityUID("Tessera::Credential", "c1")
	owner := types.NewEntityUID("Tessera::Identity", "i1")
	good := types.EntityMap{
		uid: {UID: uid, Attributes: types.NewRecord(types.RecordMap{"kind": types.String("api_key"), "age_days": types.Long(3), "holder": owner})},
	}
	if err := s.ValidateEntities(good); err != nil {
		t.Errorf("valid entity refused: %v", err)
	}
	bad := types.EntityMap{uid: {UID: uid, Attributes: types.NewRecord(types.RecordMap{"kind": types.Long(1)})}}
	if code(s.ValidateEntities(bad)) != CodeValidation {
		t.Error("ill-typed entity accepted")
	}
	many := types.EntityMap{}
	for i := 0; i <= MaxEntities; i++ {
		u := types.NewEntityUID("Tessera::Group", types.String(strings.Repeat("g", 1)+string(rune('a'+i%26))+strings.Repeat("0", i/26)))
		many[u] = types.Entity{UID: u}
	}
	if code(s.ValidateEntities(many)) != CodeTooManyEntity {
		t.Errorf("code = %q", code(s.ValidateEntities(many)))
	}
}

func TestGroupsSchema(t *testing.T) {
	s, err := GroupsSchema([]GroupAttr{{Name: "campus", Required: true}, {Name: "affiliation", Set: true}, {Name: "department"}})
	if err != nil {
		t.Fatal(err)
	}
	for src, ok := range map[string]bool{
		`permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"g") when { principal.campus == "m" };`:                                          true,
		`permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"g") when { principal.department == "m" };`:                                      false,
		`permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"g") when { principal has affiliation && principal.affiliation.contains("f") };`: true,
		`permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"g") when { principal in Tessera::Group::"x" };`:                                 true,
	} {
		if _, err := s.Check("p", []byte(src)); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok = %v", src, err, ok)
		}
	}
	for _, bad := range [][]GroupAttr{{{Name: "a b"}}, {{Name: "a"}, {Name: "a"}}} {
		if _, err := GroupsSchema(bad); code(err) != CodeSchema {
			t.Errorf("%v: err = %v", bad, err)
		}
	}
	if _, err := GroupsSchema(nil); err != nil {
		t.Errorf("no attributes: %v", err)
	}
}

func TestError_Format(t *testing.T) {
	if got := (&Error{Code: CodeSyntax, Line: 4, Msg: "x"}).Error(); got != "cedarx: syntax: line 4: x" {
		t.Error(got)
	}
	if got := (&Error{Code: CodeTooLarge, Msg: "x"}).Error(); got != "cedarx: too_large: x" {
		t.Error(got)
	}
}

// ---- fuzzing

func FuzzCheck(f *testing.F) {
	for _, s := range []string{``, `permit (principal, action, resource);`, `((((`, `"\"`, `// (`, `!!!!!!!`, `if if if`, `Set<Set<`} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, s string, schema bool) {
		err := Check([]byte(s), schema)
		if err != nil && code(err) == "" || err != nil && strings.HasPrefix(code(err), "other") {
			t.Fatalf("untyped error %v", err)
		}
	})
}

func FuzzParsePolicies(f *testing.F) {
	for _, s := range []string{
		`permit (principal, action, resource);`,
		`@id("a") forbid (principal, action == Tessera::Action::"reach", resource) when { principal.type == "human" && !(resource.tags.contains("pii")) };`,
		`permit (principal, action, resource) when { if principal.a then 1 else 2 == 3 };`,
		`permit (principal, action, resource) when { ((1 + 2) * 3 < 4) || ip("10.0.0.1").isLoopback() };`,
		`permit (principal in Group::"a", action in [Action::"x"], resource is Photo in Album::"b") unless { context.x like "a*" };`,
	} {
		f.Add(s)
	}
	schema, err := Generate(Facts{IdentityAttrs: []string{"cost_center"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ps, err := ParsePolicies("f.cedar", []byte(s))
		if err != nil {
			if code(err) == "" || strings.HasPrefix(code(err), "other") {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		_ = schema.Validate(ps) // must not panic
		// what parsed re-parses from its own text
		again, err := ParsePolicies("f.cedar", ps.Set().MarshalCedar())
		if err != nil {
			t.Fatalf("re-parse of %q: %v", ps.Set().MarshalCedar(), err)
		}
		if again.Len() != ps.Len() {
			t.Fatalf("%d policies became %d", ps.Len(), again.Len())
		}
	})
}

func FuzzParseSchema(f *testing.F) {
	g, err := Generate(Facts{IdentityAttrs: []string{"a"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(g.Text())
	f.Add([]byte(`entity A { a: Set<Set<String>> }; action x appliesTo { principal: A, resource: A };`))
	f.Add([]byte(`namespace N { type T = { a?: Long }; entity E in [E] = { t: T }; }`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := ParseSchema("f", b); err == nil {
			_, _ = s.Check("p", []byte(`permit (principal, action, resource);`)) // must not panic
		}
	})
}

// FuzzGenerate: any attribute name either generates a schema that parses or is
// refused with CodeSchema; it never reaches the schema text unchecked.
func FuzzGenerate(f *testing.F) {
	for _, s := range []string{"cost_center", "a b", "x}; entity Y {", "", "é"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		s, err := Generate(Facts{IdentityAttrs: []string{name}})
		if err != nil {
			if code(err) != CodeSchema {
				t.Fatalf("code = %q", code(err))
			}
			return
		}
		if !strings.Contains(string(s.Text()), "    "+name+"?: String") {
			t.Fatalf("attribute %q missing from the schema", name)
		}
	})
}
