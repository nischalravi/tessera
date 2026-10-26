package leastpriv_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Recommendations link to the evaluator's trace of the edge they would remove
// or trim, and have no explanation_id key when it was not evaluated (EP-8).
func TestRecommendationsExplanationID(t *testing.T) {
	grantFor := func(recs []leastpriv.Recommendation) *leastpriv.Recommendation {
		for i := range recs {
			if recs[i].IdentityName == "svc-etl" {
				return &recs[i]
			}
		}
		return nil
	}
	t.Run("absent without an evaluated edge", func(t *testing.T) {
		st, _ := testkit.Tiny(t)
		g, u := load(t, st)
		gr, trim := leastpriv.GrantRecommendations(g, u, 60, nil), leastpriv.RoleTrimRecommendations(g, u, 60, 2)
		if grantFor(gr) == nil || len(trim) == 0 {
			t.Fatalf("grant %v, trim %v; the test proves nothing", gr, trim)
		}
		for _, r := range append(gr, trim...) {
			if b, _ := json.Marshal(r); r.ExplanationID != "" || strings.Contains(string(b), "explanation_id") {
				t.Errorf("explanation_id on an unevaluated recommendation: %s", b)
			}
		}
	})
	t.Run("grant and role-trim recommendations carry the edge's trace", func(t *testing.T) {
		st, _ := testkit.Tiny(t)
		testkit.ExplainEdges(t, st, func(e *store.GrantEdge) string { return "ex:" + e.Src + ">" + e.Dst })
		g, u := load(t, st)

		gr := grantFor(leastpriv.GrantRecommendations(g, u, 60, nil))
		if gr == nil || !strings.HasPrefix(gr.ExplanationID, "ex:account:") {
			t.Fatalf("grant recommendation = %+v; want the trace of svc-etl's grant edge", gr)
		}
		if b, _ := json.Marshal(gr); !strings.Contains(string(b), `"explanation_id":"ex:account:`) {
			t.Errorf("explanation_id missing from the JSON: %s", b)
		}

		trim := leastpriv.RoleTrimRecommendations(g, u, 60, 2)
		if len(trim) != 1 || !strings.HasPrefix(trim[0].ExplanationID, "ex:group:") || !strings.Contains(trim[0].ExplanationID, ">perm:") {
			t.Fatalf("role-trim recommendations = %+v; want the trace of the role's grant edge", trim)
		}
	})
}
