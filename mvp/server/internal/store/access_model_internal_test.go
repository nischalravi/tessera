package store

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// A deployment that predates the intended and observed tables has only
// grant_edges: the first reconciliation backfills both sets from it (once).
func TestBackfillAccessModel_FromGrantEdges(t *testing.T) {
	db := openTest(t)
	if db.d == dialectPostgres {
		t.Skip("the test empties the tables through the SQLite handle")
	}
	ctx := context.Background()
	tid := tenancy.MustParse("00000000-0000-4000-8000-0000000000f1")
	if err := db.InSystem(ctx, "test", func(s *SystemTx) error {
		_, err := s.CreateTenant(Tenant{ID: tid, Slug: "backfill-tenant", Name: "backfill", CreatedAt: nowUTC()})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	err := db.InTenant(ctx, tid, func(c *TenantTx) error {
		if err := c.UpsertIdentity(&Identity{ExternalID: "u1", Name: "U One", Type: "human", Status: "active", CreatedAt: now}); err != nil {
			return err
		}
		is, _ := c.Identities()
		iid := is[0].ID
		for _, x := range []string{"a1", "a2"} {
			if err := c.UpsertAccount(&Account{System: "okta", ExternalID: x, Username: x, IdentityID: &iid, Kind: "user", Status: "active"}); err != nil {
				return err
			}
		}
		for _, x := range []string{"g1", "g2"} {
			if err := c.UpsertGroup(&Group{System: "okta", ExternalID: x, Name: x, Kind: "group"}); err != nil {
				return err
			}
		}
		as, _ := c.Accounts()
		gs, _ := c.Groups()
		node := func(kind string, id int64) string { return kind + ":" + strconv.FormatInt(id, 10) }
		if _, err := c.InsertEdge(&GrantEdge{Src: node("account", as[0].ID), Dst: node("group", gs[0].ID), Relation: "member_of",
			Source: "request", CreatedAt: now}); err != nil {
			return err
		}
		return c.UpsertConnectorEdge(node("account", as[1].ID), node("group", gs[1].ID), "member_of", now)
	})
	if err != nil {
		t.Fatal(err)
	}
	// make it look like a pre-migration database: edges only
	for _, q := range []string{`DELETE FROM intended_grants`, `DELETE FROM observed_entitlements`, `DELETE FROM observed_runs`} {
		if _, err := db.sql.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	err = db.InTenant(ctx, tid, func(c *TenantTx) error {
		ran, err := c.BackfillAccessModel(now)
		if err != nil || !ran {
			t.Fatalf("BackfillAccessModel = %v, %v", ran, err)
		}
		in, _ := c.IntendedGrants()
		if len(in) != 1 || in[0].Provenance != ProvRequest || in[0].TargetRef != "g1" || in[0].ClosedAt != nil {
			t.Errorf("intended = %+v", in)
		}
		obs, _ := c.ObservedEntitlements()
		if len(obs) != 1 || obs[0].EntitlementRef != "g2" || obs[0].AccountRef != "a2" {
			t.Errorf("observed = %+v", obs)
		}
		runs, _ := c.ObservedRuns()
		if len(runs) != 1 || runs[0].Source != ObsBackfill || runs[0].System != "okta" {
			t.Errorf("runs = %+v", runs)
		}
		if ran, err := c.BackfillAccessModel(now); err != nil || ran {
			t.Errorf("second BackfillAccessModel = %v, %v (must do nothing)", ran, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
