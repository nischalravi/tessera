package store_test

import (
	"context"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// EdgeExplanations lists the evaluator explanation of the evaluated edges of
// one campaign's review items: not another campaign's, and not another
// tenant's (EP-8).
func TestEdgeExplanations_CampaignAndTenantScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	var camp, other, edgeID int64
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		for i, dst := range []string{"perm:901", "perm:902"} {
			ev := store.EdgeEvaluation{ExplanationID: "x" + string(rune('1'+i)), Outcome: "allow", Fidelity: "exact"}
			if _, err := c.UpsertEvaluatorEdge("account:900", dst, "grants", storetest.Now, ev); err != nil {
				return err
			}
			e, err := c.EdgeBetween("account:900", dst)
			if err != nil {
				return err
			}
			id, err := c.InsertCampaign(&store.ReviewCampaign{Name: "c", CreatedAt: storetest.Now, Status: "open"})
			if err != nil {
				return err
			}
			if i == 0 {
				camp, edgeID = id, e.ID
			} else {
				other = id
			}
			if err := c.InsertReviewItem(&store.ReviewItem{CampaignID: id, IdentityID: f.A.IDs["bob"], EdgeID: &e.ID,
				EdgeSrc: e.Src, EdgeDst: e.Dst, GrantLabel: "g", Reasons: []string{}, Context: []byte(`{}`)}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		m, err := c.EdgeExplanations(camp)
		if err != nil {
			return err
		}
		if len(m) != 1 || m[edgeID] != "x1" {
			t.Errorf("campaign explanations = %v, want {%d: x1} only", m, edgeID)
		}
		if m, err = c.EdgeExplanations(f.A.IDs["campaign"]); err != nil || len(m) != 0 {
			t.Errorf("a campaign with unevaluated edges: %v, %v; want none", m, err)
		}
		if m, err = c.EdgeExplanations(other); err != nil || len(m) != 1 {
			t.Errorf("other campaign: %v, %v; want its own edge only", m, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// edgeExplanationsCovered registers this test as EdgeExplanations' isolation case
	if err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		m, err := c.EdgeExplanations(camp)
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

// edgeExplanationsCovered lists the methods TestEdgeExplanations_CampaignAndTenantScoped exercises.
func edgeExplanationsCovered() map[string]bool { return map[string]bool{"EdgeExplanations": true} }
