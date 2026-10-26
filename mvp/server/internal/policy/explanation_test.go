package policy_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// explainByEdge names an edge's explanation after its endpoints.
func explainByEdge(e *store.GrantEdge) string { return "ex:" + e.Src + ">" + e.Dst }

// A finding links to the evaluator's trace of an edge it implicates, and has
// no explanation_id key when none of its edges was evaluated (EP-8).
func TestViolationsExplanationID(t *testing.T) {
	pols := testkit.Policies(t)

	t.Run("absent without an evaluated edge", func(t *testing.T) {
		st, _ := testkit.Tiny(t)
		vs := violations(t, st, "", pols)
		if len(vs) == 0 {
			t.Fatal("no violations")
		}
		for _, v := range vs {
			b, _ := json.Marshal(v)
			if v.ExplanationID != "" || strings.Contains(string(b), "explanation_id") {
				t.Errorf("%s: explanation_id on an unevaluated finding: %s", v.PolicyID, b)
			}
		}
	})

	t.Run("policy.Evaluate names an implicated edge", func(t *testing.T) {
		st, _ := testkit.Tiny(t)
		testkit.ExplainEdges(t, st, explainByEdge)
		linked := 0
		for _, v := range violations(t, st, "", pols) {
			if len(v.Edges) == 0 {
				if v.ExplanationID != "" {
					t.Errorf("%s: explanation_id %q with no implicated edge", v.PolicyID, v.ExplanationID)
				}
				continue
			}
			ok := false
			for _, e := range v.Edges {
				ok = ok || v.ExplanationID == "ex:"+e[0]+">"+e[1]
			}
			if !ok {
				t.Errorf("%s: explanation_id %q is not the trace of one of %v", v.PolicyID, v.ExplanationID, v.Edges)
			}
			linked++
		}
		if linked == 0 {
			t.Error("no finding had implicated edges; the test proves nothing")
		}
		b, _ := json.Marshal(violations(t, st, "no-standing-prod-admin", pols)[0])
		if !strings.Contains(string(b), `"explanation_id":"ex:`) {
			t.Errorf("explanation_id missing from the JSON: %s", b)
		}
	})
}

// A SoD violation carries one trace: the effective permission's own id wins
// over the first evaluated implicated edge.
func TestSoDViolationExplanationID(t *testing.T) {
	create, approve := pat("payments:create"), pat("payments:approve")
	risks := sod.CompileBundle(sodPol(create, approve))

	t.Run("absent without an evaluated edge", func(t *testing.T) {
		st, _ := testkit.Tiny(t)
		vs := detect(t, st, risks)
		if len(vs) != 1 || vs[0].ExplanationID != "" {
			t.Fatalf("violations = %+v", vs)
		}
		if b, _ := json.Marshal(vs[0]); strings.Contains(string(b), "explanation_id") {
			t.Errorf("explanation_id in %s", b)
		}
	})

	t.Run("the permission's id wins over the edge fallback", func(t *testing.T) {
		st, ids := testkit.Tiny(t)
		// later edges get the smaller names, so the permission's sorted-first id
		// is not the first implicated edge's
		testkit.ExplainEdges(t, st, func(e *store.GrantEdge) string { return fmt.Sprintf("ex:%06d", 999999-e.ID) })
		var want, fallback string
		vs := testkit.Get(t, st, func(c *store.TenantTx) ([]sod.Violation, error) {
			g, err := graph.Build(c, testkit.Now)
			if err != nil {
				return nil, err
			}
			for _, ep := range g.EffectivePermissions(ids["bob"]).Values() {
				if ep.Action == "payments:create" {
					want = ep.ExplanationIDs[0]
				}
			}
			vs := policy.NewContext(g, c, testkit.Now).SoD(risks)
			fallback = g.EdgesExplanation(vs[0].Edges)
			return vs, nil
		})
		if len(vs) != 1 || want == "" || vs[0].ExplanationID != want {
			t.Fatalf("explanation_id = %q, want the permission's %q", vs[0].ExplanationID, want)
		}
		if fallback == want {
			t.Errorf("the edge fallback %q equals the permission's id; the test cannot tell them apart", fallback)
		}
	})
}
