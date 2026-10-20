package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Frozen review populations (issue #110): a tenant sees and changes only its
// own populations, auto-decisions and settings; a row naming another tenant's
// campaign, identity or edge is refused by the guard triggers.

func popRow(tn storetest.Tenant, ordinal int, disp string) *store.PopulationRow {
	return &store.PopulationRow{CampaignID: tn.IDs["campaign"], Ordinal: ordinal, EdgeID: tn.IDs["edge:0"],
		IdentityID: tn.IDs["bob"], IdentityRef: "bob", AccountRef: "bob", System: "okta", Entitlement: "payments-approvers",
		EdgeSrc: "account:1", EdgeDst: "group:2", InScopeReason: "standing_grant", Disposition: disp}
}

func seedPopulations(t *testing.T, f *storetest.Fixture) map[string]int64 {
	t.Helper()
	ids := map[string]int64{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		// the fixture froze one population per tenant (storetest.TwoTenants)
		ids[tn.Slug] = tn.IDs["qa"]
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.SetTenantSetting("qa_sample_pct", map[string]string{"tenant-a": "11", "tenant-b": "22"}[tn.Slug], storetest.Now)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return ids
}

func TestIsolation_PopulationReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedPopulations(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		p, err := c.ReviewPopulation(f.B.IDs["campaign"])
		if err != nil || p.PopulationHash != "fixture-hash" || p.TenantID != f.B.ID {
			t.Errorf("ReviewPopulation = %+v, %v", p, err)
		}
		if _, err := c.ReviewPopulation(f.A.IDs["campaign"]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ReviewPopulation(A's campaign) = %v", err)
		}
		rows, err := c.PopulationRows(f.A.IDs["campaign"])
		if err != nil || len(rows) != 0 {
			t.Errorf("PopulationRows(A's campaign) = %v, %v", rows, err)
		}
		ads, err := c.AutoDecisions(f.A.IDs["campaign"])
		if err != nil || len(ads) != 0 {
			t.Errorf("AutoDecisions(A's campaign) = %v, %v", ads, err)
		}
		if _, err := c.AutoDecision(ids[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AutoDecision(A's) = %v", err)
		}
		if v, ok, err := c.TenantSetting("qa_sample_pct"); err != nil || !ok || v != "22" {
			t.Errorf("TenantSetting = %q %v %v, want B's 22", v, ok, err)
		}
		return nil
	})
}

func TestIsolation_PopulationWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedPopulations(t, f)
	ctx := context.Background()
	// B cannot decide A's QA item
	err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.QADecideAutoDecision(ids[f.A.Slug], "revoke", nil, storetest.Now, store.UserRef{})
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("QA decision on A's item from B = %v, want ErrNotFound", err)
	}
	// B naming A's campaign, identity or edge is refused by the guards
	for name, mut := range map[string]func(*store.PopulationRow){
		"campaign": func(r *store.PopulationRow) { r.CampaignID = f.A.IDs["campaign"] },
		"identity": func(r *store.PopulationRow) { r.IdentityID = f.A.IDs["alice"] },
		"edge":     func(r *store.PopulationRow) { r.EdgeID = f.A.IDs["edge:1"] },
	} {
		row := popRow(f.B, 2, "review")
		mut(row)
		err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
			return c.InsertReviewPopulation(&store.ReviewPopulation{CampaignID: f.B.IDs["campaign"] + 1000, CreatedAt: storetest.Now,
				PopulationHash: "x", SystemCounts: json.RawMessage(`{}`), SourceSyncs: json.RawMessage(`{}`),
				Scope: json.RawMessage(`{}`), RulesVersion: "v"}, []*store.PopulationRow{row})
		})
		if err == nil {
			t.Errorf("row naming A's %s was accepted", name)
		}
	}
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAutoDecision(&store.AutoDecision{CampaignID: f.A.IDs["campaign"], Ordinal: 9, EdgeID: f.B.IDs["edge:0"],
			IdentityID: f.B.IDs["bob"], Rule: json.RawMessage(`{}`)})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("auto-decision naming A's campaign = %v, want ErrCrossTenant", err)
	}
	// a caller-supplied tenant is refused
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		r := popRow(f.B, 3, "review")
		r.TenantID = f.A.ID
		return c.InsertReviewPopulation(&store.ReviewPopulation{TenantID: f.A.ID}, []*store.PopulationRow{r})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("row stamped with A's tenant = %v, want ErrCrossTenant", err)
	}
	// A's data is untouched
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		ads, err := c.AutoDecisions(f.A.IDs["campaign"])
		if err != nil || len(ads) != 1 || ads[0].QADecision != nil {
			t.Errorf("A's auto-decisions = %+v, %v", ads, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func populationCovered() map[string]bool {
	return map[string]bool{"ReviewPopulation": true, "PopulationRows": true, "AutoDecisions": true, "AutoDecision": true,
		"TenantSetting":          true, // TestIsolation_PopulationReads
		"InsertReviewPopulation": true, "InsertAutoDecision": true, "QADecideAutoDecision": true,
		"SetTenantSetting": true} // TestIsolation_PopulationWritesScoped
}
