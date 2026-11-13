package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The summary kept for an applied change request (schema/0967_admin_change_summaries.sql, issue #977) is the tenant's
// own: B reads none of A's, cannot keep one for A's request (guard trigger; composite foreign key in Postgres), and a
// second write for the same request replaces the first.
func TestIsolation_AdminChangeSummaries(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, _ := seedAdminRows(t, f)
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if err := c.SetAdminChangeSummary(a.pending.ID, "first"); err != nil {
			return err
		}
		return c.SetAdminChangeSummary(a.pending.ID, "a@x → b@x")
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if s, err := c.AdminChangeSummary(a.pending.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's summary = %q, %v", s, err)
		}
		return nil
	})
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.SetAdminChangeSummary(a.pending.ID, "forged")
	}); err == nil {
		t.Error("B kept a summary for A's change request")
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if s, err := c.AdminChangeSummary(a.pending.ID); err != nil || s != "a@x → b@x" {
			t.Errorf("A's summary = %q, %v", s, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func adminSummariesCovered() map[string]bool {
	return map[string]bool{"SetAdminChangeSummary": true, "AdminChangeSummary": true}
}
