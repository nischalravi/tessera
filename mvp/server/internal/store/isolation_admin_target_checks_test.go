package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The approver's URL-check attempts (schema/0964_change_target_checks.sql, issue #886) are the tenant's own: B counts none
// of A's, cannot file one against A's request (guard trigger; the composite foreign key in Postgres), and the same
// user id in B is B's own count.
func TestIsolation_AdminChangeTargetChecks(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedAdminRows(t, f)
	now := storetest.Now
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if err := c.InsertAdminChangeTargetCheck(a.pending.ID, "approver-1", "0123456789abcdef", false, now); err != nil {
			return err
		}
		return c.InsertAdminChangeTargetCheck(a.pending.ID, "approver-1", "0123456789abcdef", true, now)
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if n, err := c.AdminChangeTargetChecks(a.pending.ID); err != nil || n != 0 {
			t.Errorf("B counts A's checks = %d, %v", n, err)
		}
		if n, err := c.AdminChangeTargetChecksBy("approver-1", now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("B counts A's approver = %d, %v", n, err)
		}
		return nil
	})
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAdminChangeTargetCheck(a.pending.ID, "approver-1", "0123456789abcdef", false, now)
	}); err == nil {
		t.Error("B filed a check against A's change request")
	}
	inB(t, f, func(c *store.TenantTx) error {
		return c.InsertAdminChangeTargetCheck(b.pending.ID, "approver-1", "fedcba9876543210", false, now)
	})
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if n, err := c.AdminChangeTargetChecks(a.pending.ID); err != nil || n != 2 {
			t.Errorf("A's checks = %d, %v", n, err)
		}
		if n, err := c.AdminChangeTargetChecks(b.pending.ID); err != nil || n != 0 {
			t.Errorf("A counts B's checks = %d, %v", n, err)
		}
		if n, err := c.AdminChangeTargetChecksBy("approver-1", now.Add(-time.Hour)); err != nil || n != 2 {
			t.Errorf("A's approver count = %d, %v", n, err)
		}
		if n, err := c.AdminChangeTargetChecksBy("approver-1", now.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("a window after the checks = %d, %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func adminTargetChecksCovered() map[string]bool {
	return map[string]bool{"InsertAdminChangeTargetCheck": true, "AdminChangeTargetChecks": true, "AdminChangeTargetChecksBy": true} // the test above
}
