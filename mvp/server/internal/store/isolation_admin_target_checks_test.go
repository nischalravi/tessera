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
		if err := c.InsertAdminChangeTargetCheck(a.pending.ID, "approver-1", "0123456789abcdef", "sealedA", false, now); err != nil {
			return err
		}
		return c.InsertAdminChangeTargetCheck(a.pending.ID, "approver-1", "0123456789abcdef", "sealedA", true, now)
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if n, err := c.AdminChangeTargetChecksOf("sealedA", now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("B counts A's checks of a value = %d, %v", n, err)
		}
		if n, err := c.AdminChangeTargetChecksTenant(now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("B counts A's checks of the tenant = %d, %v", n, err)
		}
		if n, err := c.AdminChangeTargetChecksBy("approver-1", now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("B counts A's approver = %d, %v", n, err)
		}
		return nil
	})
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAdminChangeTargetCheck(a.pending.ID, "approver-1", "0123456789abcdef", "sealedA", false, now)
	}); err == nil {
		t.Error("B filed a check against A's change request")
	}
	inB(t, f, func(c *store.TenantTx) error {
		return c.InsertAdminChangeTargetCheck(b.pending.ID, "approver-1", "fedcba9876543210", "sealedA", false, now)
	})
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if n, err := c.AdminChangeTargetChecksOf("sealedA", now.Add(-time.Hour)); err != nil || n != 2 {
			t.Errorf("A's checks of the value = %d, %v", n, err)
		}
		if n, err := c.AdminChangeTargetChecksTenant(now.Add(-time.Hour)); err != nil || n != 2 {
			t.Errorf("A's tenant checks = %d, %v", n, err)
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
	return map[string]bool{"InsertAdminChangeTargetCheck": true, "AdminChangeTargetChecksOf": true, "AdminChangeTargetChecksTenant": true, "AdminChangeTargetChecksBy": true,
		"AdminChangeTargetFilingsTenant": true,
		"InsertAdminChangeTargetFiling":  true, "AdminChangeTargetFiling": true} // the test above
}

// The server-side comparison kept when a proposal is filed against an existing object is the tenant's own: B reads none of A's,
// cannot file one against A's request, and a filing is counted against its object's key in its own tenant only.
func TestIsolation_AdminChangeTargetFiling(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedAdminRows(t, f)
	now := storetest.Now
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.InsertAdminChangeTargetFiling(a.pending.ID, "tsc_x", "0123456789abcdef", "objkey", "unchanged", "livefp", now)
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if fl, lf, err := c.AdminChangeTargetFiling(a.pending.ID); err != nil || fl != "" || lf != "" {
			t.Errorf("B reads A's comparison = %q %q, %v", fl, lf, err)
		}
		if n, err := c.AdminChangeTargetChecksOf("objkey", now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("B counts A's object = %d, %v", n, err)
		}
		if n, err := c.AdminChangeTargetFilingsTenant(now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("B counts A's filings = %d, %v", n, err)
		}
		return nil
	})
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAdminChangeTargetFiling(a.pending.ID, "tsc_x", "0123456789abcdef", "objkey", "unchanged", "livefp", now)
	}); err == nil {
		t.Error("B filed a comparison against A's change request")
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if fl, lf, err := c.AdminChangeTargetFiling(a.pending.ID); err != nil || fl != "unchanged" || lf != "livefp" {
			t.Errorf("A's comparison = %q %q, %v", fl, lf, err)
		}
		if fl, _, err := c.AdminChangeTargetFiling(b.pending.ID); err != nil || fl != "" {
			t.Errorf("A reads B's comparison = %q, %v", fl, err)
		}
		// a filing is not an approver's check (#907)
		if n, err := c.AdminChangeTargetFilingsTenant(now.Add(-time.Hour)); err != nil || n != 1 {
			t.Errorf("A's filings = %d, %v", n, err)
		}
		if n, err := c.AdminChangeTargetChecksTenant(now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("A's approver checks count the filing = %d, %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
