package store_test

import (
	"context"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// EdgeExplanations lists the evaluator explanation of each evaluated edge of
// the tenant, and only its own (EP-8).
func TestEdgeExplanations_TenantScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	ev := store.EdgeEvaluation{ExplanationID: "x1", Outcome: "allow", Fidelity: "exact"}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		_, err := c.UpsertEvaluatorEdge("account:900", "perm:901", "grants", storetest.Now, ev)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		e, err := c.EdgeBetween("account:900", "perm:901")
		if err != nil {
			return err
		}
		m, err := c.EdgeExplanations()
		if err != nil {
			return err
		}
		if len(m) != 1 || m[e.ID] != "x1" {
			t.Errorf("tenant A explanations = %v, want {%d: x1}", m, e.ID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		m, err := c.EdgeExplanations()
		if err != nil {
			return err
		}
		if len(m) != 0 {
			t.Errorf("tenant B sees %v", m)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
