package seed_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	guestlife "github.com/nischalravi/tessera/mvp/server/internal/guests/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestSeedDemoGuestLifecycle: with DemoGuestLifecycle on, the lifecycle page has a
// sponsorship expiring in 10 days and one pending transfer; off, nothing is added.
func TestSeedDemoGuestLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	for _, on := range []bool{false, true} {
		db, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"))
		if err != nil {
			t.Fatal(err)
		}
		conns, err := connectors.Load("", now)
		if err != nil {
			t.Fatal(err)
		}
		tn := seed.Larkspur(conns)
		tn.Identifiers, tn.DemoGuestLifecycle = storetest.IdentityKeyer(t), on
		if _, err := seed.Run(ctx, db, now, testkitPolicies(t), []seed.Tenant{tn}); err != nil {
			t.Fatal(err)
		}
		err = db.ReadTenant(ctx, seed.LarkspurID, func(c *store.TenantTx) error {
			counts, err := guestlife.Counts(c, now)
			if err != nil {
				return err
			}
			if !on {
				if counts[guestlife.BucketExpiring30] != 0 || counts[guestlife.BucketPendingTransfer] != 0 {
					t.Errorf("rows seeded with the demo off: %v", counts)
				}
				return nil
			}
			if counts[guestlife.BucketExpiring14] != 1 || counts[guestlife.BucketPendingTransfer] != 1 {
				t.Errorf("demo counts = %v", counts)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
	}
}
