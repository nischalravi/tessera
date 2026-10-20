package policygroups

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var genGroups = []string{"ref:a", "ref:b", "ref:c", "app:x:manual", "app:x:deny"}

// lower-cased name as the id: the compiled form is then readable in a failure
func idByName(name string) (string, error) { return strings.ToLower(name), nil }

func mustParse(t testing.TB, group, src string) *File {
	t.Helper()
	f, diags := ParseFile(group+".cedar", src, testSchema())
	if len(diags) > 0 {
		t.Fatalf("%v\n%s", diags, src)
	}
	return f
}

// leafOf evaluates a compiled leaf the way the engine's attribute groups and
// reference groups would hold it, for a fake subject.
func leafOf(s fakeSubject, schema Schema) func(*Node) bool {
	return func(n *Node) bool {
		switch n.Kind {
		case KindGroup:
			return s.groups[n.Name]
		case store.NodeAttr, store.NodeHas:
			name, _, ok := schema.attrDef(n.Attr)
			if !ok {
				return false
			}
			return memberOfAttr(schema, s.attrs[name], n)
		}
		return false
	}
}

// checkEquivalent compiles a random policy file and compares the compiled tree
// with the naive evaluation of the policies on random subjects. It reports
// whether the file compiled (a policy can be refused as unbounded; the generator
// avoids that, so a refusal is itself a failure).
func checkEquivalent(t testing.TB, seed int64) {
	t.Helper()
	g := newGen(seed, genGroups)
	f := mustParse(t, "app:x:pol", g.file("app:x:pol"))
	c := NewCompiler()
	plan, diags := c.Compile(f, idByName)
	if len(diags) > 0 {
		t.Fatalf("seed %d: %v\n%s", seed, diags, g.file("app:x:pol"))
	}
	root := plan.Result(c)
	// the same plan, by a second compiler, is the same tree
	plan2, _ := NewCompiler().Compile(f, idByName)
	if plan2.Digest() != plan.Digest() {
		t.Fatalf("seed %d: compiling twice gave %s and %s", seed, plan.Digest(), plan2.Digest())
	}
	for i := 0; i < 64; i++ {
		s := g.subject()
		want, err := f.Decide(s)
		if err != nil {
			t.Fatal(err)
		}
		if got := root.Eval(leafOf(s, testSchema())); got != want {
			t.Fatalf("seed %d: compiled = %v, naive = %v for %+v\n%s", seed, got, want, s, g.file("app:x:pol"))
		}
	}
}

// TestCompile_EquivalentToNaive: the compiled composite tree (allow minus deny
// over hash-consed nodes) is the same set as evaluating the policies directly.
func TestCompile_EquivalentToNaive(t *testing.T) {
	n := 600
	if testing.Short() {
		n = 100
	}
	for seed := int64(1); seed <= int64(n); seed++ {
		checkEquivalent(t, seed)
	}
}

func FuzzCompile_EquivalentToNaive(f *testing.F) {
	for _, s := range []int64{1, 2, 3, 42, 1 << 40} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, seed int64) { checkEquivalent(t, seed) })
}

func compileOne(t *testing.T, c *Compiler, cond string) (*Plan, []Diagnostic) {
	t.Helper()
	return c.Compile(mustParse(t, "app:foo:pol", one(cond)), idByName)
}

func TestCompile_Algebra(t *testing.T) {
	const A, B, C = `principal in Tessera::Group::"a"`, `principal in Tessera::Group::"b"`, `principal in Tessera::Group::"c"`
	c := NewCompiler()
	kind := func(cond string) string {
		p, ds := compileOne(t, c, cond)
		if len(ds) > 0 {
			return "ERR " + ds[0].Code
		}
		return p.Allow.Kind
	}
	for cond, want := range map[string]string{
		A:                                     KindGroup,
		A + " && " + B:                        store.NodeIntersection,
		A + " || " + B:                        store.NodeUnion,
		A + " && !(" + B + ")":                store.NodeComplement,
		A + " && (" + B + " || !(" + C + "))": store.NodeComplement,
		A + " && " + A:                        KindGroup,
		A + " || " + A:                        KindGroup,
		A + " && !(" + A + ")":                store.NodeEmpty,
		"!(" + A + ") || " + B:                "ERR " + CodeUnbounded,
		"!(" + A + ")":                        "ERR " + CodeUnbounded,
		"!(" + A + ") && !(" + B + ")":        "ERR " + CodeUnbounded,
		"!(!(" + A + "))":                     KindGroup,
		"!(" + A + " || " + B + ") && " + C:   store.NodeComplement,
	} {
		if got := kind(cond); got != want {
			t.Errorf("%s: %s, want %s", cond, got, want)
		}
	}
	// a refusal names the policy and its position
	_, ds := compileOne(t, c, "!("+A+")")
	if len(ds) != 1 || ds[0].Line != 1 || !strings.Contains(ds[0].Msg, "every identity except") {
		t.Errorf("unbounded diagnostic: %+v", ds)
	}
	// a group that does not resolve is a finding at its position
	f := mustParse(t, "app:foo:pol", one(A+" && "+B))
	_, ds = c.Compile(f, func(name string) (string, error) {
		if name == "b" {
			return "", fmt.Errorf("no group named %q", name)
		}
		return name, nil
	})
	if len(ds) != 1 || ds[0].Code != CodeUnknownGroup || ds[0].Col < 10 {
		t.Errorf("unresolved group: %+v", ds)
	}
}

// TestCompile_AllowMinusDeny: E(policy) = (union of permits) - (union of forbids).
func TestCompile_AllowMinusDeny(t *testing.T) {
	src := `permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:pol") when { principal in Tessera::Group::"a" };
permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:pol") when { principal in Tessera::Group::"b" };
forbid (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:pol") when { principal in Tessera::Group::"c" };`
	c := NewCompiler()
	plan, ds := c.Compile(mustParse(t, "p", src), idByName)
	if len(ds) > 0 {
		t.Fatal(ds)
	}
	if plan.Allow.Kind != store.NodeUnion || len(plan.Allow.Kids) != 2 || plan.Deny.Kind != KindGroup || plan.Deny.Name != "c" {
		t.Errorf("allow = %+v, deny = %+v", plan.Allow, plan.Deny)
	}
	// permits only: deny is empty; forbids only: allow is empty
	plan, _ = c.Compile(mustParse(t, "p", one(`principal in Tessera::Group::"a"`)), idByName)
	if plan.Deny.Kind != store.NodeEmpty || plan.Allow.Name != "a" {
		t.Errorf("permit only: %+v / %+v", plan.Allow, plan.Deny)
	}
	plan, _ = c.Compile(mustParse(t, "p", fhdr+` when { principal in Tessera::Group::"a" };`), idByName)
	if plan.Allow.Kind != store.NodeEmpty || plan.Result(c).Kind != store.NodeEmpty {
		t.Errorf("forbid only: %+v", plan.Allow)
	}
	// allow and deny the same set: nothing is a member
	both := hdr + ` when { principal in Tessera::Group::"a" };` + fhdr + ` when { principal in Tessera::Group::"a" };`
	plan, _ = c.Compile(mustParse(t, "p", both), idByName)
	if got := plan.Result(c); got.Kind != store.NodeEmpty {
		t.Errorf("a - a = %+v", got)
	}
	if fs := factorsOf(c, plan); len(fs) != 2 || fs[0].Hash == fs[1].Hash {
		t.Errorf("factors of a - a must be two different groups: %+v", fs)
	}
}

// TestHashConsing_SharesSubtrees: identical subtrees, however written and in
// whichever file, are one node.
func TestHashConsing_SharesSubtrees(t *testing.T) {
	const A, B, C = `principal in Tessera::Group::"a"`, `principal in Tessera::Group::"b"`, `principal in Tessera::Group::"c"`
	c := NewCompiler()
	faculty := A + ` || (` + B + ` && principal.campus == "main")`
	p1, _ := compileOne(t, c, faculty+` || `+C)
	p2, _ := compileOne(t, c, C+` || (principal.campus == "main" && `+B+`) || `+A)
	p3, _ := compileOne(t, c, `(`+A+` || `+C+`) || (`+B+` && principal.campus == "main")`)
	if p1.Allow != p2.Allow || p1.Allow != p3.Allow {
		t.Fatalf("one union written three ways is three nodes: %s %s %s", p1.Allow.Hash, p2.Allow.Hash, p3.Allow.Hash)
	}
	if p1.Digest() != p2.Digest() {
		t.Error("equal compiled forms have different digests")
	}
	// a subtree shared by two different policies is the same node
	pa, _ := compileOne(t, c, faculty)
	pb, _ := compileOne(t, c, `(`+faculty+`) && principal in Tessera::Group::"d"`)
	shared := map[*Node]bool{}
	for _, n := range pa.Reach() {
		shared[n] = true
	}
	n := 0
	for _, x := range pb.Reach() {
		if shared[x] {
			n++
		}
	}
	if n < 3 { // the intersection node, the campus leaf, the union
		t.Errorf("only %d nodes shared between a policy and one built on it", n)
	}
	// 400 policies that all say the same compile to the same two roots
	roots := map[string]bool{}
	for i := 0; i < 400; i++ {
		p, _ := compileOne(t, c, faculty)
		roots[p.Allow.Hash+"/"+p.Deny.Hash] = true
	}
	if len(roots) != 1 {
		t.Errorf("400 identical policies compiled to %d forms", len(roots))
	}
	// different attribute values or groups are different nodes
	d1, _ := compileOne(t, c, `principal.campus == "main"`)
	d2, _ := compileOne(t, c, `principal.campus == "north"`)
	d3, _ := compileOne(t, c, `principal.campus == "main" && `+A)
	if d1.Allow == d2.Allow || d1.Allow == d3.Allow {
		t.Error("distinct sets share a node")
	}
	// the attribute name is not case-sensitive in a node (group names are not)
	if c.Attr("Campus", "main") != c.Attr("campus", "main") {
		t.Error("an attribute node depends on the case of the attribute")
	}
}

// TestCompile_LongListsAreSplit: a union of more groups than a composite may
// have factors becomes a tree of unions, and means the same set.
func TestCompile_LongListsAreSplit(t *testing.T) {
	var names, conds []string
	for i := 0; i < 250; i++ {
		n := fmt.Sprintf("ref:g%03d", i)
		names = append(names, n)
		conds = append(conds, fmt.Sprintf("principal in Tessera::Group::%q", n))
	}
	c := NewCompiler()
	plan, ds := compileOne(t, c, strings.Join(conds, " || "))
	if len(ds) > 0 {
		t.Fatal(ds)
	}
	for _, n := range plan.Reach() {
		if len(n.Kids) > engine.MaxFactors {
			t.Errorf("node %s has %d operands (limit %d)", n.Hash, len(n.Kids), engine.MaxFactors)
		}
	}
	for _, in := range []string{"ref:g000", "ref:g137", "ref:g249"} {
		s := fakeSubject{groups: map[string]bool{in: true}}
		if !plan.Allow.Eval(leafOf(s, testSchema())) {
			t.Errorf("member of %s is not in the split union", in)
		}
	}
	if plan.Allow.Eval(leafOf(fakeSubject{groups: map[string]bool{"ref:other": true}}, testSchema())) {
		t.Error("a non-member is in the split union")
	}
	// the same for an intersection
	plan, _ = compileOne(t, c, strings.ReplaceAll(strings.Join(conds, " || "), "||", "&&"))
	all := fakeSubject{groups: map[string]bool{}}
	for _, n := range names {
		all.groups[n] = true
	}
	if !plan.Allow.Eval(leafOf(all, testSchema())) {
		t.Error("an identity in every group is not in the split intersection")
	}
	delete(all.groups, "ref:g200")
	if plan.Allow.Eval(leafOf(all, testSchema())) {
		t.Error("an identity missing one group is in the split intersection")
	}
}

// TestRoundTrip: a rendered condition parses back to the same condition.
func TestRoundTrip(t *testing.T) {
	g := newGen(7, genGroups)
	for i := 0; i < 200; i++ {
		e := g.policyCond()
		f := mustParse(t, "app:foo:pol", one(String(e)))
		if got, want := String(f.Policies[0].Cond), String(e); got != want {
			t.Fatalf("round trip:\n got %s\nwant %s", got, want)
		}
	}
}
