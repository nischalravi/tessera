package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestPopulationImmutability: a frozen population can be neither updated nor
// deleted, an auto-decision keeps its rule and sample flag, and a QA decision
// is recorded once (schema/0207_review_populations.sql).
func TestPopulationImmutability(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	var tid tenancy.ID
	if err := db.InSystem(ctx, "test", func(s *SystemTx) error {
		x, err := s.CreateTenant(Tenant{Slug: "tenant-p", Name: "P"})
		tid = x.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var camp int64
	if err := db.InTenant(ctx, tid, func(tx *TenantTx) error {
		var err error
		if camp, err = tx.InsertCampaign(&ReviewCampaign{Name: "c", CreatedAt: nowUTC(), Status: "open"}); err != nil {
			return err
		}
		if err := tx.InsertReviewPopulation(&ReviewPopulation{CampaignID: camp, CreatedAt: nowUTC(), PopulationHash: "h",
			ItemCount: 1, SystemCounts: json.RawMessage(`{}`), SourceSyncs: json.RawMessage(`{}`), Scope: json.RawMessage(`{}`),
			RulesVersion: "v"}, []*PopulationRow{{CampaignID: camp, Ordinal: 1, EdgeID: 7, IdentityID: 1, IdentityRef: "i",
			AccountRef: "a", System: "s", Entitlement: "e", EdgeSrc: "account:1", EdgeDst: "group:1", InScopeReason: "standing_grant",
			Disposition: "auto_certified"}}); err != nil {
			return err
		}
		return tx.InsertAutoDecision(&AutoDecision{CampaignID: camp, Ordinal: 1, EdgeID: 7, IdentityID: 1,
			Rule: json.RawMessage(`{}`), QASample: true})
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, sql, want string }{
		{"population update", `UPDATE review_populations SET population_hash = 'x'`, "immutable"},
		{"population delete", `DELETE FROM review_populations`, "immutable"},
		{"row update", `UPDATE review_population_rows SET system = 'x'`, "immutable"},
		{"row delete", `DELETE FROM review_population_rows`, "immutable"},
		{"rule update", `UPDATE review_auto_decisions SET decided_by_rule = '{"x":1}'`, "immutable"},
		{"sample flag update", `UPDATE review_auto_decisions SET qa_sample = 0`, "immutable"},
		{"auto-decision delete", `DELETE FROM review_auto_decisions`, "append-only"},
	} {
		_, err := db.sql.ExecContext(ctx, tc.sql)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	// a QA decision is allowed once
	if err := db.InTenant(ctx, tid, func(tx *TenantTx) error {
		ads, err := tx.AutoDecisions(camp)
		if err != nil || len(ads) != 1 {
			t.Fatalf("auto-decisions %v %v", ads, err)
		}
		if err := tx.QADecideAutoDecision(ads[0].ID, "revoke", nil, nowUTC(), UserRef{}); err != nil {
			t.Errorf("first QA decision: %v", err)
		}
		if err := tx.QADecideAutoDecision(ads[0].ID, "keep", nil, nowUTC(), UserRef{}); err != ErrNotFound {
			t.Errorf("second QA decision = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE review_auto_decisions SET qa_decision = 'keep'`); err == nil ||
		!strings.Contains(err.Error(), "already recorded") {
		t.Errorf("raw second QA update: %v", err)
	}
}
