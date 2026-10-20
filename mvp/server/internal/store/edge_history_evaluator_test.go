package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// An edge the AWS evaluator confirms keeps edge_history in step like every
// other write to grant_edges: a new edge opens a span, a changed relation
// closes it and opens another, and deleting the edge closes the last one.
func TestEdgeHistory_EvaluatorEdge(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	t0, t1, t2 := storetest.Now, storetest.Now.Add(time.Hour), storetest.Now.Add(2*time.Hour)
	ev := store.EdgeEvaluation{ExplanationID: "x", Outcome: "allow", Fidelity: "approximate"}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		for _, step := range []struct {
			rel string
			at  time.Time
		}{{"grants", t0}, {"grants", t0.Add(time.Minute)}, {"admin", t1}} {
			if ok, err := c.UpsertEvaluatorEdge("account:900", "perm:901", step.rel, step.at, ev); err != nil || !ok {
				t.Fatalf("UpsertEvaluatorEdge = %v, %v", ok, err)
			}
		}
		e, err := c.EdgeBetween("account:900", "perm:901")
		if err != nil {
			return err
		}
		return c.DeleteEdge(e.ID, t2)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		all, err := c.EdgeSpans()
		if err != nil {
			return err
		}
		var spans []*store.EdgeSpan
		for _, s := range all {
			if s.Src == "account:900" && s.Dst == "perm:901" {
				spans = append(spans, s)
			}
		}
		if len(spans) != 2 {
			t.Fatalf("%d spans, want 2 (grants, then admin)", len(spans))
		}
		for _, s := range spans {
			if s.ValidTo == nil {
				t.Errorf("span %s left open after DeleteEdge", s.Relation)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
