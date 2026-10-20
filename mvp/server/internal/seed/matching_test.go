package seed_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// TestSeedDemoMatching: with DemoMatching on, the review queue has one item: a
// guest invited at an employee's personal address, flagged and not linked. With
// it off (the default, and the tests') nothing is added.
func TestSeedDemoMatching(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	for _, on := range []bool{false, true} {
		db, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"))
		if err != nil {
			t.Fatal(err)
		}
		conns, err := connectors.Load("", now) // the demo connectors `tessera seed` uses
		if err != nil {
			t.Fatal(err)
		}
		tn := seed.Larkspur(conns)
		tn.Identifiers, tn.DemoMatching = storetest.IdentityKeyer(t), on
		if _, err := seed.Run(ctx, db, now, testkitPolicies(t), []seed.Tenant{tn}); err != nil {
			t.Fatal(err)
		}
		err = db.ReadTenant(ctx, seed.LarkspurID, func(c *store.TenantTx) error {
			rows, err := c.MatchResults(store.MatchFilter{Status: store.MatchReview})
			if err != nil {
				return err
			}
			if !on {
				if len(rows) != 0 {
					t.Errorf("%d matches seeded with the demo off", len(rows))
				}
				return nil
			}
			if len(rows) != 1 || rows[0].Tier != "C" || rows[0].CandidateID == nil || rows[0].SubjectID == nil ||
				!strings.Contains(rows[0].Rules, "verified_email") || rows[0].Outcome != store.MatchOutcomeSuspected {
				t.Fatalf("demo match = %+v", rows)
			}
			guest, err := c.Identity(*rows[0].SubjectID)
			if err != nil || guest.Status != "invited" {
				t.Errorf("the guest = %+v, %v", guest, err)
			}
			if ss, _ := c.Sponsorships(store.SponsorshipFilter{Guest: guest.ID}); len(ss) != 1 {
				t.Errorf("sponsorships = %v", ss)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
	}
}

func testkitPolicies(t *testing.T) []*policy.Policy { return testkit.Policies(t) }
