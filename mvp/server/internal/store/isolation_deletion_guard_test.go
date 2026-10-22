package store_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func deletionGuardCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"DeletionPolicies", "PutDeletionPolicy", "DeletionSettingsRow", "PutDeletionSettings", "LockDeletionCategory",
		"DeletionsApplied", "RecordDeletions", "DeletionPopulation", "InsertDeletionHold", "DeletionHoldByID", "DeletionHolds",
		"DeletionHoldsDue", "OpenDeletionHolds", "DeletionHoldItems", "SetDeletionHoldItem", "ResolveDeletionHold",
		"OpenDeletionHoldByCorrelation", "AppendDeletionHoldItems"} {
		out[k] = true // TestIsolation_DeletionGuard
	}
	return out
}

// The deletion guard's policies, ledger and held deletions (schema/0670) are per tenant: another
// tenant's window does not count against this one, cannot see, resolve or extend its holds, and a
// hold item cannot point at another tenant's hold.
func TestIsolation_DeletionGuard(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	ten := 10
	var hold store.DeletionHold
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.PutDeletionPolicy(&store.DeletionPolicy{Category: "groups", MaxCount: &ten, WindowMinutes: 60, Mode: "hold_excess"}, now); err != nil {
			return err
		}
		if err := c.PutDeletionSettings(24, nil, now); err != nil {
			return err
		}
		if err := c.LockDeletionCategory("groups"); err != nil {
			return err
		}
		if err := c.RecordDeletions("groups", 7, "user", now, now.Add(-time.Hour)); err != nil {
			return err
		}
		hold = store.DeletionHold{Category: "groups", Mode: "hold_excess", Reason: "{}", Actor: "u", Source: "user", CorrelationID: "corr-1",
			CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		return c.InsertDeletionHold(&hold, []store.DeletionHoldItem{{Kind: "group_delete", Ref: "g1", Label: "g1"}})
	})
	before := storetest.Dump(t, f.DB, f.A.ID)

	inB(t, f, func(c *store.TenantTx) error {
		if ps, err := c.DeletionPolicies(); err != nil || len(ps) != 0 {
			t.Errorf("DeletionPolicies = %v, %v", ps, err)
		}
		if _, err := c.DeletionSettingsRow(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeletionSettingsRow = %v", err)
		}
		if n, err := c.DeletionsApplied("groups", now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("DeletionsApplied = %d, %v (A's ledger counted)", n, err)
		}
		if _, err := c.DeletionHoldByID(hold.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeletionHoldByID(A's) = %v", err)
		}
		if hs, err := c.DeletionHolds("", "", 100, 0); err != nil || len(hs) != 0 {
			t.Errorf("DeletionHolds = %v, %v", hs, err)
		}
		if hs, err := c.DeletionHoldsDue(now.Add(48 * time.Hour)); err != nil || len(hs) != 0 {
			t.Errorf("DeletionHoldsDue = %v, %v", hs, err)
		}
		if _, err := c.OpenDeletionHoldByCorrelation("groups", "corr-1"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OpenDeletionHoldByCorrelation(A's) = %v", err)
		}
		if n, err := c.OpenDeletionHolds(); err != nil || n != 0 {
			t.Errorf("OpenDeletionHolds = %d, %v", n, err)
		}
		if its, err := c.DeletionHoldItems(hold.ID); err != nil || len(its) != 0 {
			t.Errorf("DeletionHoldItems(A's) = %v, %v", its, err)
		}
		if err := c.ResolveDeletionHold(hold.ID, "discarded", "b", "", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ResolveDeletionHold(A's) = %v", err)
		}
		if err := c.SetDeletionHoldItem(hold.ID, 0, "released", ""); err != nil {
			t.Errorf("SetDeletionHoldItem(A's) = %v", err)
		}
		// an item cannot be added to A's hold from B
		if err := c.AppendDeletionHoldItems(&hold, []store.DeletionHoldItem{{Kind: "group_delete", Ref: "g2"}}); err == nil {
			t.Errorf("B appended an item to A's hold")
		}
		return nil
	})
	if after := storetest.Dump(t, f.DB, f.A.ID); !reflect.DeepEqual(before, after) {
		t.Errorf("tenant A's rows changed by tenant B's calls")
	}
	// the window is per tenant: A's 7 are A's alone
	inA(t, f, func(c *store.TenantTx) error {
		if n, err := c.DeletionsApplied("groups", now.Add(-time.Hour)); err != nil || n != 7 {
			t.Errorf("A's window = %d, %v, want 7", n, err)
		}
		return nil
	})
}
