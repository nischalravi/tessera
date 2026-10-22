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
		"OpenDeletionHoldByCorrelation", "AppendDeletionHoldItems", "SetDeletionHoldReason",
		"DeletionSourcePolicies", "DeletionSourcePoliciesOf", "DeletionSourcePolicy", "PutDeletionSourcePolicy", "DeleteDeletionSourcePolicy",
		"DeletionSourceCount", "PutDeletionSourceCount", "DeletionsAppliedBySource", "RecordSourceDeletions"} {
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
		drop, off := 50.0, false
		if err := c.PutDeletionSourcePolicy(&store.DeletionSourcePolicy{Kind: "connection", SourceID: "conn-1", Category: "identities",
			Mode: "hold_excess", MaxCount: &ten, WindowMinutes: 30, FeedDropPercent: &drop, FeedEmptyCheck: &off}, now); err != nil {
			return err
		}
		if err := c.PutDeletionSourceCount("connection", "conn-1", "identities", 120, now); err != nil {
			return err
		}
		if err := c.RecordSourceDeletions("connection", "conn-1", "identities", 4, now, now.Add(-time.Hour)); err != nil {
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
		if ps, err := c.DeletionSourcePolicies(); err != nil || len(ps) != 0 {
			t.Errorf("DeletionSourcePolicies = %v, %v (A's override listed)", ps, err)
		}
		if ps, err := c.DeletionSourcePoliciesOf("connection", "conn-1"); err != nil || len(ps) != 0 {
			t.Errorf("DeletionSourcePoliciesOf(A's) = %v, %v", ps, err)
		}
		if _, err := c.DeletionSourcePolicy("connection", "conn-1", "identities"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeletionSourcePolicy(A's) = %v", err)
		}
		if _, ok, err := c.DeletionSourceCount("connection", "conn-1", "identities"); err != nil || ok {
			t.Errorf("DeletionSourceCount(A's) = %v, %v", ok, err)
		}
		if n, err := c.DeletionsAppliedBySource("connection", "conn-1", "identities", now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("DeletionsAppliedBySource = %d, %v (A's ledger counted)", n, err)
		}
		// B writing the same source id makes its own rows and leaves A's alone
		if err := c.DeleteDeletionSourcePolicy("connection", "conn-1", "identities"); err != nil {
			t.Errorf("DeleteDeletionSourcePolicy = %v", err)
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
		if err := c.SetDeletionHoldReason(hold.ID, "{}"); err != nil {
			t.Errorf("SetDeletionHoldReason(A's) = %v", err)
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
		if p, err := c.DeletionSourcePolicy("connection", "conn-1", "identities"); err != nil || p.Mode != "hold_excess" || p.WindowMinutes != 30 ||
			p.FeedEmptyCheck == nil || *p.FeedEmptyCheck || *p.FeedDropPercent != 50 {
			t.Errorf("A's override = %+v, %v", p, err)
		}
		if n, ok, err := c.DeletionSourceCount("connection", "conn-1", "identities"); err != nil || !ok || n != 120 {
			t.Errorf("A's last count = %d %v %v", n, ok, err)
		}
		if n, err := c.DeletionsAppliedBySource("connection", "conn-1", "identities", now.Add(-time.Hour)); err != nil || n != 4 {
			t.Errorf("A's source window = %d, %v, want 4", n, err)
		}
		if n, err := c.DeletionsApplied("groups", now.Add(-time.Hour)); err != nil || n != 7 {
			t.Errorf("A's window = %d, %v, want 7", n, err)
		}
		return nil
	})
}
