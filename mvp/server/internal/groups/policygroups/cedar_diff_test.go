package policygroups

import (
	"fmt"
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

// cedarSrc is src as stock Cedar reads it: the fragment is Cedar's grammar
// (issue #698), so it is src itself.
func cedarSrc(src string) string { return src }

// checkAgainstCedar fails if the fragment accepts src and cedar-go does not.
func checkAgainstCedar(t testing.TB, cs *cedarx.Schema, schema Schema, src string) {
	f, diags := ParseFile("p.cedar", src, schema)
	if f == nil || len(diags) > 0 {
		return
	}
	if _, err := cs.Check("p.cedar", []byte(cedarSrc(src))); err != nil {
		t.Fatalf("the fragment accepts what cedar-go refuses: %v\n%s", err, src)
	}
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

// The four forms the fragment once accepted and Cedar refuses (issue #698) are
// refused by both now, with a finding that names the Cedar spelling.
func TestCedar_FormerDivergencesAgree(t *testing.T) {
	schema := testSchema()
	cs := cedarGroupsSchema(t, schema)
	for name, c := range map[string]struct {
		src, hint string
	}{
		"string in list":        {one(`principal.campus in ["a", "b"]`), `.contains(principal.campus)`},
		"multi-value provision": {`@provision("ldap", "entra") ` + one(`principal has campus`), `@provision("ldap,entra")`},
		"guard into unless":     {hdr + ` when { principal has department } unless { principal.department == "x" };`, "same when or unless clause"},
		"guard into when":       {hdr + ` when { principal has department } when { principal.department == "x" };`, "same when or unless clause"},
		"NUL in a string":       {one("principal.campus == \"a\x00b\""), "control character"},
		"newline in a string":   {one("principal.campus == \"a\nb\""), "control character"},
		"bell in a string":      {one("principal.campus == \"a\x07b\""), "control character"},
	} {
		t.Run(name, func(t *testing.T) {
			f, diags := ParseFile("p.cedar", c.src, schema)
			if f != nil || len(diags) == 0 || !strings.Contains(diags[0].Msg, c.hint) || diags[0].Line == 0 {
				t.Errorf("the fragment: file = %v, diags = %v; want a finding with %q", f, diags, c.hint)
			}
			if _, err := cs.Check("p.cedar", []byte(c.src)); err == nil && !strings.Contains(name, "bell") {
				t.Error("cedar-go accepts it; the finding is stricter than Cedar")
			}
		})
	}
}

// The Cedar spellings of those forms are accepted by both, with the same meaning.
func TestCedar_CedarSpellingsAgree(t *testing.T) {
	schema := testSchema()
	cs := cedarGroupsSchema(t, schema)
	for name, src := range map[string]string{
		"list contains":      one(`["a", "b"].contains(principal.campus)`),
		"one provision":      `@provision("ldap,entra") ` + one(`principal has campus`),
		"guard in unless":    hdr + ` when { principal has department && !(principal.department == "x") };`,
		"guard in an unless": hdr + ` when { principal has campus } unless { principal has department && principal.department == "x" };`,
		"escaped newline":    one(`principal.campus == "a\nb"`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, diags := ParseFile("p.cedar", src, schema); len(diags) > 0 {
				t.Errorf("the fragment: %v", diags)
			}
			if _, err := cs.Check("p.cedar", []byte(src)); err != nil {
				t.Errorf("cedar-go: %v", err)
			}
		})
	}
	f, diags := ParseFile("p.cedar", `@provision("ldap, entra,ldap") `+one(`principal has campus`), schema)
	if len(diags) > 0 || strings.Join(f.Provision, "|") != "ldap|entra" {
		t.Errorf("provision targets: %v %v", f, diags)
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
	f.Add(one(`["a", "b"].contains(principal.campus)`))
	f.Add(`@provision("a,b") ` + one(`principal has campus`))
	f.Add(one("principal.campus == \"a\x00b\""))
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
