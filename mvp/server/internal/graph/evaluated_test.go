package graph

import (
	"slices"
	"testing"
)

// settle combines the evaluated paths of one permission (design §11.2): it is
// conditional only if every path is, its fidelity is the best of the paths
// that decide it, and a path no evaluation touches settles it on its own.
func TestSettle(t *testing.T) {
	cond := func(f string, ids ...string) pathEval {
		return pathEval{conditional: true, fidelity: f, explanation: ids}
	}
	allow := func(f string, ids ...string) pathEval { return pathEval{fidelity: f, explanation: ids} }
	for _, tc := range []struct {
		name  string
		pes   []pathEval
		total int
		cond  bool
		fid   string
		ids   []string
	}{
		{"one allow", []pathEval{allow("exact", "a")}, 1, false, "exact", []string{"a"}},
		{"one conditional", []pathEval{cond("exact", "a")}, 1, true, "exact", []string{"a"}},
		{"allow beats conditional", []pathEval{cond("exact", "c"), allow("approximate", "a")}, 2, false, "approximate", []string{"a"}},
		{"best fidelity of the deciding paths", []pathEval{allow("approximate", "b"), allow("exact", "a")}, 2, false, "exact", []string{"a", "b"}},
		{"all conditional: best of all", []pathEval{cond("unsupported", "u"), cond("approximate", "p")}, 2, true, "approximate", []string{"p", "u"}},
		{"an unevaluated path settles it", []pathEval{cond("exact", "c")}, 2, false, "", nil},
		{"unevaluated beside an evaluated allow", []pathEval{allow("approximate", "a")}, 2, false, "approximate", []string{"a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f, ids := settle(tc.pes, tc.total)
			if c != tc.cond || f != tc.fid || !slices.Equal(ids, tc.ids) {
				t.Errorf("settle = (%v, %q, %v), want (%v, %q, %v)", c, f, ids, tc.cond, tc.fid, tc.ids)
			}
		})
	}
}

// pathEval takes the worst fidelity of the evaluated edges of a path and is
// conditional if any of them is; a path with no evaluated edge reports none.
func TestPathEval(t *testing.T) {
	g := New()
	for _, k := range []string{"identity:1", "account:1", "group:1", "perm:1", "perm:2"} {
		g.AddNode(&Node{Key: k, Kind: k[:len(k)-2], Status: "active"})
	}
	g.setEdge("identity:1", "account:1", &Edge{Relation: "has_account", Source: "connector"})
	g.setEdge("account:1", "group:1", &Edge{Relation: RelCanAssume, Source: "evaluator", Outcome: OutcomeConditional, Fidelity: FidelityExact, ExplanationID: "t"})
	g.setEdge("group:1", "perm:1", &Edge{Relation: "grants", Source: "evaluator", Outcome: OutcomeAllow, Fidelity: FidelityApprox, ExplanationID: "g"})
	g.setEdge("group:1", "perm:2", &Edge{Relation: "grants", Source: "connector"})

	pe, ok := g.pathEval([]string{"identity:1", "account:1", "group:1", "perm:1"})
	if !ok || !pe.conditional || pe.fidelity != FidelityApprox || !slices.Equal(pe.explanation, []string{"t", "g"}) {
		t.Errorf("pathEval = %+v, %v; want conditional, approximate, [t g]", pe, ok)
	}
	if _, ok := g.pathEval([]string{"identity:1", "account:1"}); ok {
		t.Error("a path of unevaluated edges reports an evaluation")
	}

	// the permission through the conditional trust edge is conditional, with the evidence of its path
	eff := g.EffectivePermissions(1)
	ep := eff.M["perm:1"]
	if ep == nil || !ep.Conditional || ep.Fidelity != FidelityApprox || !slices.Equal(ep.ExplanationIDs, []string{"g", "t"}) {
		t.Errorf("perm:1 = %+v; want conditional, approximate, [g t]", ep)
	}
	// perm:2 is reached only through the same conditional trust edge, and its own edge is unevaluated
	if ep := eff.M["perm:2"]; ep == nil || ep.Conditional != true {
		t.Errorf("perm:2 = %+v; want conditional by the trust edge", ep)
	}
}

// EdgesExplanation returns the first implicated edge's explanation id, and ""
// when none of them was evaluated (EP-8).
func TestEdgesExplanation(t *testing.T) {
	g := New()
	for _, k := range []string{"account:1", "group:1", "perm:1"} {
		g.AddNode(&Node{Key: k, Kind: k[:len(k)-2], Status: "active"})
	}
	g.setEdge("account:1", "group:1", &Edge{Relation: "member", Source: "connector"})
	g.setEdge("group:1", "perm:1", &Edge{Relation: "grants", Source: "evaluator", Outcome: OutcomeAllow, Fidelity: FidelityExact, ExplanationID: "g"})
	for _, tc := range []struct {
		name  string
		edges [][]string
		want  string
	}{
		{"none", nil, ""},
		{"unevaluated only", [][]string{{"account:1", "group:1"}}, ""},
		{"absent edge", [][]string{{"x", "y"}}, ""},
		{"first evaluated", [][]string{{"account:1", "group:1"}, {"group:1", "perm:1"}}, "g"},
	} {
		if got := g.EdgesExplanation(tc.edges); got != tc.want {
			t.Errorf("%s: EdgesExplanation = %q, want %q", tc.name, got, tc.want)
		}
	}
}
