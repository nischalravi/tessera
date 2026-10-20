package policygroups

import (
	"strings"
	"testing"
)

// testSchema is the design's example schema: the identity attributes of §8.4.
func testSchema() Schema {
	return Schema{Attrs: map[string]AttrDef{
		"campus":      {Type: AttrString, Required: true},
		"department":  {Type: AttrString},
		"affiliation": {Type: AttrSet},
		"title":       {Type: AttrString},
	}}
}

const hdr = `permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:pol")`
const fhdr = `forbid (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:pol")`

func one(cond string) string { return hdr + " when { " + cond + " };" }

// designExample is the file of design §8.3.
const designExample = `
@group("app:foo:service:policy:foo_user")
@display("Foo users")
@owner("app:foo:security:fooAdmin")
@provision("ldap-main", "entra")
@id("allow")
permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:service:policy:foo_user")
when {
  principal in Tessera::Group::"ref:employee:faculty" ||
  (principal in Tessera::Group::"ref:student:enrolled" && principal.campus == "main") ||
  principal in Tessera::Group::"app:foo:service:policy:foo_user_allow_manual"
};

// the deny side
@id("deny")
forbid (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:service:policy:foo_user")
when {
  principal in Tessera::Group::"ref:iam:global_deny" ||
  principal in Tessera::Group::"app:foo:service:policy:foo_user_deny_manual"
};
`

func TestFragment_AcceptsDesignExample(t *testing.T) {
	f, diags := ParseFile("groups/app/foo/foo_user.cedar", designExample, testSchema())
	if len(diags) > 0 {
		t.Fatalf("diagnostics: %v", diags)
	}
	if f.Group != "app:foo:service:policy:foo_user" || f.Display != "Foo users" || f.Owner != "app:foo:security:fooAdmin" ||
		len(f.Provision) != 2 || len(f.Policies) != 2 || f.Policies[0].ID != "allow" || f.Policies[1].Effect != Forbid {
		t.Fatalf("file = %+v", f)
	}
	groups, at := f.Groups()
	if len(groups) != 5 || groups[0] != "app:foo:service:policy:foo_user_allow_manual" {
		t.Errorf("groups = %v", groups)
	}
	if p := at["ref:iam:global_deny"]; p.Line != 18 || p.Col != 16 {
		t.Errorf("position of ref:iam:global_deny = %v", p)
	}
}

// TestFragment_RejectsUnsupported: everything outside the fragment of design §8.2
// fails with a precise finding (context, resource attributes, arithmetic, dates
// and extension functions, and the rest of Cedar's grammar).
func TestFragment_RejectsUnsupported(t *testing.T) {
	cases := []struct {
		name, src, code, msg string
	}{
		{"context", one(`context.ip == "x"`), CodeUnsupported, "context is not available"},
		{"context in a group test", one(`principal in Tessera::Group::"a" && context.mfa == "x"`), CodeUnsupported, "context is not available"},
		{"resource attribute", one(`resource.owner == "x"`), CodeUnsupported, "resource attributes are not available"},
		{"resource has", one(`resource has owner`), CodeUnsupported, "resource attributes are not available"},
		{"action in condition", one(`action == Tessera::Action::"member"`), CodeUnsupported, "action is not available"},
		{"arithmetic", one(`principal.campus == "a" && 1 + 1 == 2`), CodeUnsupported, "arithmetic"},
		{"arithmetic on an attribute", one(`principal.campus + 1 == 2`), CodeUnsupported, "arithmetic"},
		{"negative number", one(`-1 == 2`), CodeUnsupported, "arithmetic"},
		{"multiplication", one(`2 * 3 == 6`), CodeUnsupported, "arithmetic"},
		{"comparison", one(`principal.campus < "z"`), CodeUnsupported, "comparison operators"},
		{"not equal", one(`principal.campus != "z"`), CodeUnsupported, "!="},
		{"datetime", one(`datetime("2026-01-01") == datetime("2026-01-01")`), CodeUnsupported, "extension functions"},
		{"ip", one(`ip("10.0.0.1").isLoopback()`), CodeUnsupported, "extension functions"},
		{"decimal", one(`decimal("1.0") == decimal("1.0")`), CodeUnsupported, "extension functions"},
		{"like", one(`principal.campus like "ma*"`), CodeUnsupported, "'like'"},
		{"is", one(`principal is User`), CodeUnsupported, "'is'"},
		{"if", one(`if true then true else false`), CodeUnsupported, "if-then-else"},
		{"record", one(`{ a: 1 }.a == 1`), CodeUnsupported, "records"},
		{"boolean literal", one(`true`), CodeUnsupported, "combines groups"},
		{"string literal", one(`"x"`), CodeUnsupported, "combines groups"},
		{"nested attribute", one(`principal.name.first == "x"`), CodeUnsupported, ""},
		{"nested has", one(`principal has name.first`), CodeUnsupported, "nested attributes"},
		{"a bare attribute", one(`principal.campus`), CodeUnsupported, "not used as a condition"},
		{"unsupported method", one(`principal.campus.isEmpty()`), CodeUnsupported, "is not supported"},
		{"containsAll", one(`principal.affiliation.containsAll(["a"])`), CodeUnsupported, "is not supported"},
		{"entity of another type", one(`principal in User::"x"`), CodeUnsupported, "names a group"},
		{"in with a non-literal list", one(`principal.campus in [principal.title]`), CodeUnsupported, "string literals"},
		{"attribute compared with an attribute", one(`principal.campus == principal.title`), CodeUnsupported, "string literal"},
		{"scope constraint", `permit (principal in Tessera::Group::"x", action == Tessera::Action::"member", resource == Tessera::Group::"g") when { principal has campus };`, CodeUnsupported, "principal constraint"},
		{"wrong action", `permit (principal, action == Tessera::Action::"read", resource == Tessera::Group::"g") when { principal has campus };`, CodeInvalidPolicy, "member"},
		{"wrong resource type", `permit (principal, action == Tessera::Action::"member", resource == Tessera::Folder::"g") when { principal has campus };`, CodeInvalidPolicy, "Tessera::Group"},
		{"no condition", hdr + `;`, CodeInvalidPolicy, "needs a when or unless"},
		{"unknown attribute", one(`principal.shoe == "x"`), CodeUnknownAttr, "declares no attribute"},
		{"unknown attribute in has", one(`principal has shoe`), CodeUnknownAttr, "declares no attribute"},
		{"contains on a string", one(`principal.campus.contains("x")`), CodeTypeMismatch, "is a string"},
		{"equals on a set", one(`principal has affiliation && principal.affiliation == "x"`), CodeTypeMismatch, "is a set"},
		{"unguarded optional attribute", one(`principal.department == "x"`), CodeUnguardedAttr, "optional"},
		{"guard on the wrong side", one(`principal.department == "x" && principal has department`), CodeUnguardedAttr, "optional"},
		{"guard under or", one(`principal has department || principal.department == "x"`), CodeUnguardedAttr, "optional"},
		{"guard under not", one(`!(principal has department) && principal.department == "x"`), CodeUnguardedAttr, "optional"},
		{"empty value", one(`principal.campus == ""`), CodeInvalidValue, "not empty"},
		{"long value", one(`principal.campus == "` + strings.Repeat("a", MaxValueBytes+1) + `"`), CodeInvalidValue, "at most"},
		{"empty list", one(`principal.campus in []`), CodeUnsupported, "empty"},
		{"two groups in one file", one(`principal has campus`) + "\n" + strings.Replace(hdr, "app:foo:pol", "app:foo:other", 1) + ` when { principal has campus };`, CodeInvalidPolicy, "one group"},
		{"@group disagrees", `@group("a:b") ` + one(`principal has campus`), CodeInvalidPolicy, "@group must name"},
		{"unknown annotation", `@shoe("x") ` + one(`principal has campus`), CodeInvalidPolicy, "unknown annotation"},
		{"duplicate id", `@id("a") ` + one(`principal has campus`) + `@id("a") ` + one(`principal has campus`), CodeInvalidPolicy, "used twice"},
		{"bad group name", strings.Replace(one(`principal has campus`), "app:foo:pol", "a b", 1), CodeInvalidPolicy, "not a valid group name"},
		{"unterminated string", one(`principal.campus == "x`), CodeSyntax, "unterminated"},
		{"single equals", one(`principal.campus = "x"`), CodeSyntax, "'=='"},
		{"single ampersand", one(`principal has campus & principal has campus`), CodeSyntax, "'&&'"},
		{"missing semicolon", hdr + ` when { principal has campus }`, CodeSyntax, "expected ';'"},
		{"unknown name", one(`foo`), CodeSyntax, "unknown name"},
		{"stray character", one(`principal has campus #`), CodeSyntax, "unexpected character"},
		{"empty file", ``, CodeInvalidPolicy, "at least one"},
		{"comment only", `// nothing`, CodeInvalidPolicy, "at least one"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, diags := ParseFile("p.cedar", c.src, testSchema())
			if f != nil || len(diags) == 0 {
				t.Fatalf("accepted: %+v", f)
			}
			found := false
			for _, d := range diags {
				if d.Code == c.code && strings.Contains(d.Msg, c.msg) {
					found = true
				}
				if d.Path != "p.cedar" || d.Line < 1 || d.Col < 1 {
					t.Errorf("diagnostic without a position: %+v", d)
				}
			}
			if !found {
				t.Errorf("no %s finding containing %q in %v", c.code, c.msg, diags)
			}
		})
	}
}

func TestFragment_AcceptsTheFragment(t *testing.T) {
	for name, cond := range map[string]string{
		"group":              `principal in Tessera::Group::"a:b"`,
		"group list":         `principal in [Tessera::Group::"a:b", Tessera::Group::"a:c"]`,
		"required attribute": `principal.campus == "main"`,
		"attribute in":       `principal.campus in ["a", "b"]`,
		"set contains":       `principal has affiliation && principal.affiliation.contains("faculty")`,
		"guarded":            `principal has department && principal.department == "cs"`,
		"guard dominates":    `principal has department && (principal.department == "cs" || principal.department == "math")`,
		"negation":           `principal in Tessera::Group::"a" && !(principal.campus == "x")`,
		"has":                `principal has title`,
		"nested":             `((principal in Tessera::Group::"a" || principal in Tessera::Group::"b") && !(principal in Tessera::Group::"c")) || principal.campus == "m"`,
		"escapes":            `principal.campus == "caf\u{e9}\n\"q\" \\"`,
		"unicode value":      `principal.campus == "café"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, diags := ParseFile("p.cedar", one(cond), testSchema()); len(diags) > 0 {
				t.Fatalf("%v", diags)
			}
		})
	}
	// an unless clause is a negated condition, and it is checked like one
	if f, diags := ParseFile("p.cedar", hdr+` when { principal has department } unless { principal.department == "x" };`, testSchema()); len(diags) > 0 || len(f.Policies) != 1 {
		t.Errorf("unless: %v", diags)
	}
	if _, diags := ParseFile("p.cedar", hdr+` unless { principal.department == "x" };`, testSchema()); len(diags) == 0 {
		t.Error("an unguarded attribute in an unless was accepted")
	}
}

func TestParse_Limits(t *testing.T) {
	deep := strings.Repeat("(", 200) + `principal has campus` + strings.Repeat(")", 200)
	if _, diags := ParseFile("p.cedar", one(deep), testSchema()); len(diags) == 0 || !strings.Contains(diags[0].Msg, "nested") {
		t.Errorf("deep nesting: %v", diags)
	}
	if _, diags := ParseFile("p.cedar", strings.Repeat("// x\n", MaxFileBytes/5+1), testSchema()); len(diags) == 0 || diags[0].Code != CodeFileTooLarge {
		t.Errorf("a huge file: %v", diags)
	}
	// bare Not chains are bounded too
	if _, diags := ParseFile("p.cedar", one(strings.Repeat("!", 500)+`(principal has campus)`), testSchema()); len(diags) == 0 {
		t.Error("a chain of 500 negations was accepted")
	}
}

func TestSchema_Validate(t *testing.T) {
	for name, s := range map[string]Schema{
		"bad name":  {Attrs: map[string]AttrDef{"a b": {Type: AttrString}}},
		"bad type":  {Attrs: map[string]AttrDef{"a": {Type: "long"}}},
		"case":      {Attrs: map[string]AttrDef{"Dept": {Type: AttrString}, "dept": {Type: AttrString}}},
		"set req":   {Attrs: map[string]AttrDef{"a": {Type: AttrSet, Required: true}}},
		"too long":  {Attrs: map[string]AttrDef{strings.Repeat("a", 65): {Type: AttrString}}},
		"leading 1": {Attrs: map[string]AttrDef{"1a": {Type: AttrString}}},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := DefaultSchema().Validate(); err != nil {
		t.Errorf("default schema: %v", err)
	}
}

func TestEncodeValue(t *testing.T) {
	seen := map[string]string{}
	for _, v := range []string{"main", "Main", "MAIN", "a b", "a_b", "a-b", "a.b", "é", "_5f", "x/y", "0", ".", ".."} {
		e := EncodeValue(v)
		if strings.ToLower(e) != e || strings.Trim(e, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			t.Errorf("EncodeValue(%q) = %q is not a lower-case name segment", v, e)
		}
		if other, dup := seen[strings.ToLower(e)]; dup {
			t.Errorf("%q and %q both encode to %q", v, other, e)
		}
		seen[strings.ToLower(e)] = v
	}
	if EncodeValue("main") != "main" || EncodeValue("a b") != "a_20b" {
		t.Errorf("EncodeValue: %q %q", EncodeValue("main"), EncodeValue("a b"))
	}
}
