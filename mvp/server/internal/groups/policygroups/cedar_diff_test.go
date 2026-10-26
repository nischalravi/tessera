package policygroups

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/nischalravi/tessera/mvp/server/internal/cedarx"
)

// Differential tests of the restricted fragment parser against cedar-go (AC-1):
// everything the fragment accepts is valid Cedar under the schema generated from
// the same attribute declarations, and the fragment's decision for a subject is
// the one cedar-go's authorizer gives for the same policies.

// cedarGroupsSchema is cedarx's groups schema for the fragment Schema.
func cedarGroupsSchema(t testing.TB, s Schema) *cedarx.Schema {
	t.Helper()
	var attrs []cedarx.GroupAttr
	for name, d := range s.Attrs {
		attrs = append(attrs, cedarx.GroupAttr{Name: name, Set: d.Type == AttrSet, Required: d.Required})
	}
	cs, err := cedarx.GroupsSchema(attrs)
	if err != nil {
		t.Fatalf("groups schema: %v", err)
	}
	return cs
}

// attrInList matches the fragment's `principal.attr in ["a", "b"]`.
var attrInList = regexp.MustCompile(`(principal\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)\s+in\b\s*(\[[^\]]*\])`)

// cedarSrc is src as stock Cedar reads it, where the fragment is a superset of
// Cedar in two ways the differential finds (reported in the PR for AC-1):
//   - @provision takes a list of strings (design §8.3); a Cedar annotation takes
//     one value, so the list is joined with a comma;
//   - `principal.attr in [..]` tests a string attribute against a list; in Cedar
//     `in` is entity hierarchy membership and is a type error on strings, so it
//     is the equivalent `[..].contains(principal.attr)`.
func cedarSrc(src string) string {
	src = attrInList.ReplaceAllString(src, "$2.contains($1)")
	var out []string
	for _, ln := range strings.Split(src, "\n") {
		if t := strings.TrimSpace(ln); strings.HasPrefix(t, "@provision(") {
			ln = "@provision(" + `"` + strings.Join(provisionTargets(t), ",") + `")`
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func provisionTargets(line string) []string {
	body := strings.TrimSuffix(strings.TrimPrefix(line, "@provision("), ")")
	var out []string
	for _, p := range strings.Split(body, ",") {
		out = append(out, strings.Trim(strings.TrimSpace(p), `"`))
	}
	return out
}

// checkAgainstCedar fails if the fragment accepts src and cedar-go does not.
func checkAgainstCedar(t testing.TB, cs *cedarx.Schema, schema Schema, src string) {
	f, diags := ParseFile("p.cedar", src, schema)
	if f == nil || len(diags) > 0 {
		return
	}
	if _, err := cs.Check("p.cedar", []byte(cedarSrc(src))); err != nil && !unlessGuardDivergence(src, err) && !controlCharDivergence(src) {
		t.Fatalf("the fragment accepts what cedar-go refuses: %v\n%s", err, src)
	}
}

// unlessGuardDivergence is the third known divergence: the fragment checks the
// clauses of a policy as one conjunction, so a `when { principal has x }`
// guards `unless { principal.x == .. }`; Cedar's validator checks each clause on
// its own and refuses the unless as unguarded. Pinned by
// TestCedar_UnlessGuardIsAnExtension.
func unlessGuardDivergence(src string, err error) bool {
	return strings.Contains(src, "unless") && strings.Contains(err.Error(), "unable to guarantee safety")
}

// TestCedar_FragmentIsValidCedar: the design example and 400 generated files.
func TestCedar_FragmentIsValidCedar(t *testing.T) {
	schema := testSchema()
	cs := cedarGroupsSchema(t, schema)
	f, diags := ParseFile("p.cedar", designExample, schema)
	if f == nil {
		t.Fatalf("design example: %v", diags)
	}
	if _, err := cs.Check("p.cedar", []byte(cedarSrc(designExample))); err != nil {
		t.Fatalf("design example under cedar-go: %v", err)
	}
	for seed := int64(1); seed <= 400; seed++ {
		g := newGen(seed, []string{"a:one", "a:two", "b:three"})
		src := g.file("app:x:pol")
		if f, diags := ParseFile("p.cedar", src, schema); f == nil {
			t.Fatalf("seed %d: generated file rejected: %v\n%s", seed, diags, src)
		}
		checkAgainstCedar(t, cs, schema, src)
	}
}

// TestCedar_RejectionsAgree: what the fragment refuses for being ill-typed or
// unguarded is also refused by the Cedar validator; what it refuses only for
// being outside the fragment is still valid Cedar (the fragment is a subset).
func TestCedar_RejectionsAgree(t *testing.T) {
	schema := testSchema()
	cs := cedarGroupsSchema(t, schema)
	for name, c := range map[string]struct {
		cond      string
		cedarSays bool // valid Cedar under the schema
	}{
		"unguarded optional":       {`principal.department == "x"`, false},
		"guard on the wrong side":  {`principal.department == "x" && principal has department`, false},
		"guard under or":           {`principal has department || principal.department == "x"`, false},
		"guard under not":          {`!(principal has department) && principal.department == "x"`, false},
		"contains on a string":     {`principal.campus.contains("x")`, false},
		"equals on a set":          {`principal has affiliation && principal.affiliation == "x"`, false},
		"unknown attribute":        {`principal.shoe == "x"`, false},
		"unknown attribute in has": {`principal has shoe`, true}, // Cedar: false at run time, not an error
		"entity of another type":   {`principal in User::"x"`, false},
		"not equal":                {`principal.campus != "z"`, true},
		"like":                     {`principal.campus like "ma*"`, true},
		"if":                       {`if principal.campus == "a" then true else false`, true},
		"arithmetic":               {`principal.campus == "a" && 1 + 1 == 2`, true},
		"boolean literal":          {`true`, true},
	} {
		t.Run(name, func(t *testing.T) {
			src := one(c.cond)
			f, _ := ParseFile("p.cedar", src, schema)
			_, err := cs.Check("p.cedar", []byte(src))
			if f != nil {
				t.Fatalf("the fragment accepts %q", c.cond)
			}
			if (err == nil) != c.cedarSays {
				t.Errorf("cedar-go: err = %v, want valid = %v", err, c.cedarSays)
			}
		})
	}
}

// TestCedar_AttrInListIsAnExtension pins the divergence: the fragment accepts a
// string attribute `in` a list, Cedar rejects it, and cedarSrc's rewrite is valid.
func TestCedar_AttrInListIsAnExtension(t *testing.T) {
	schema := testSchema()
	cs := cedarGroupsSchema(t, schema)
	src := one(`principal.campus in ["a", "b"]`)
	if f, diags := ParseFile("p.cedar", src, schema); f == nil {
		t.Fatalf("the fragment refuses it: %v", diags)
	}
	if _, err := cs.Check("p.cedar", []byte(src)); err == nil {
		t.Error("cedar-go accepts `string in list`; the rewrite in cedarSrc is no longer needed")
	}
	if _, err := cs.Check("p.cedar", []byte(cedarSrc(src))); err != nil {
		t.Errorf("the rewritten form is refused: %v", err)
	}
}

// controlCharDivergence is the fourth: the fragment's lexer lets a raw control
// character (NUL, for one) into a string literal, which Cedar's lexer refuses.
// Pinned by TestCedar_ControlCharacterIsAnExtension.
func controlCharDivergence(src string) bool {
	for i := 0; i < len(src); i++ {
		if c := src[i]; c < 0x20 && c != '\n' && c != '\t' && c != '\r' || c == 0x7f {
			return true
		}
	}
	return false
}

func TestCedar_ControlCharacterIsAnExtension(t *testing.T) {
	schema := testSchema()
	cs := cedarGroupsSchema(t, schema)
	src := one("principal.campus == \"a\x00b\"")
	if f, _ := ParseFile("p.cedar", src, schema); f == nil {
		t.Skip("the fragment now refuses control characters; drop controlCharDivergence")
	}
	if _, err := cs.Check("p.cedar", []byte(src)); err == nil {
		t.Error("cedar-go accepts a NUL in a string; drop controlCharDivergence")
	}
}

// TestCedar_UnlessGuardIsAnExtension pins the divergence of a guard in `when`
// covering an attribute read in `unless`; the fix is to put the guard in the
// unless (`unless { principal has x && principal.x == .. }` is not equivalent,
// so the author writes the whole condition in one when).
func TestCedar_UnlessGuardIsAnExtension(t *testing.T) {
	schema := testSchema()
	cs := cedarGroupsSchema(t, schema)
	src := hdr + ` when { principal has department } unless { principal.department == "x" };`
	if f, diags := ParseFile("p.cedar", src, schema); f == nil {
		t.Fatalf("the fragment refuses it: %v", diags)
	}
	_, err := cs.Check("p.cedar", []byte(src))
	if err == nil || !unlessGuardDivergence(src, err) {
		t.Errorf("cedar-go: err = %v; if it accepts now, drop unlessGuardDivergence", err)
	}
}

// cedarDecide authorizes subject s on group `group` with the policies in src.
func cedarDecide(t testing.TB, ps *cedarx.Policies, group string, s fakeSubject, groups []string) bool {
	t.Helper()
	var parents []types.EntityUID
	for _, g := range groups {
		if s.groups[strings.ToLower(g)] {
			parents = append(parents, types.NewEntityUID("Tessera::Group", types.String(g)))
		}
	}
	rec := types.RecordMap{}
	for name, vals := range s.attrs {
		switch name {
		case "affiliation":
			var set []types.Value
			for _, v := range vals {
				set = append(set, types.String(v))
			}
			rec[types.String(name)] = types.NewSet(set...)
		default:
			rec[types.String(name)] = types.String(vals[0])
		}
	}
	me := types.NewEntityUID("Tessera::Identity", "u1")
	entities := types.EntityMap{me: types.Entity{UID: me, Parents: types.NewEntityUIDSet(parents...), Attributes: types.NewRecord(rec)}}
	dec, _ := ps.Set().IsAuthorized(entities, cedar.Request{
		Principal: me,
		Action:    types.NewEntityUID("Tessera::Action", "member"),
		Resource:  types.NewEntityUID("Tessera::Group", types.String(group)),
		Context:   types.NewRecord(nil),
	})
	return dec == cedar.Allow
}

// TestCedar_DecisionsAgree: for random files and subjects, the fragment's
// decision (a permit and no forbid) is cedar-go's authorizer's.
func TestCedar_DecisionsAgree(t *testing.T) {
	schema := testSchema()
	groups := []string{"a:one", "a:two", "b:three"}
	n := 300
	if testing.Short() {
		n = 50
	}
	for seed := int64(1); seed <= int64(n); seed++ {
		g := newGen(seed, groups)
		src := g.file("app:x:pol")
		f, diags := ParseFile("p.cedar", src, schema)
		if f == nil {
			t.Fatalf("seed %d: %v", seed, diags)
		}
		ps, err := cedarx.ParsePolicies("p.cedar", []byte(cedarSrc(src)))
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for i := 0; i < 24; i++ {
			s := g.subject()
			want, err := f.Decide(s)
			if err != nil {
				t.Fatal(err)
			}
			if got := cedarDecide(t, ps, "app:x:pol", s, groups); got != want {
				t.Fatalf("seed %d: fragment = %v, cedar-go = %v for %s\n%s", seed, want, got, fmt.Sprint(s), src)
			}
		}
	}
}

// FuzzFragmentAgainstCedar: whatever the fragment parser accepts, cedar-go
// parses and validates.
func FuzzFragmentAgainstCedar(f *testing.F) {
	f.Add(designExample)
	f.Add(one(`principal in Tessera::Group::"a:b" && !(principal.campus == "x")`))
	f.Add(one(`principal has department && principal.department == "cs"`))
	f.Add(hdr + ` when { principal has department } unless { principal.department == "x" };`)
	f.Add(one(`principal has affiliation && principal.affiliation.contains("faculty")`))
	f.Add(one(`principal.campus == "caf\u{e9}\n\"q\" \\"`))
	for seed := int64(1); seed <= 8; seed++ {
		f.Add(newGen(seed, []string{"a:one", "b:two"}).file("app:x:pol"))
	}
	schema := testSchema()
	cs := cedarGroupsSchema(f, schema)
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 8<<10 {
			return
		}
		checkAgainstCedar(t, cs, schema, src)
	})
}
