package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Who asked to disable an account through the account route (schema/0965_account_disable_requests.sql, issue #915) is
// the tenant's own: B sees none of A's records, cannot file one against A's account (guard trigger; composite foreign
// key in Postgres), and B's own record for the same external account is separate. Held deletion items are read per tenant.
func TestIsolation_AccountDisableRequests(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	acct := func(tn storetest.Tenant) int64 { return tn.IDs["acct:okta:alice"] }
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.RecordAccountDisableRequest(acct(f.A), "admin-a", nil, now)
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if r, err := c.AccountDisableRequest(acct(f.A)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's record = %+v, %v", r, err)
		}
		if r, err := c.AccountDisableRequest(acct(f.B)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B's own account has A's record = %+v, %v", r, err)
		}
		if refs, err := c.HeldDeletionItemRefs("prov_op", `"Key":"account-state:`); err != nil || len(refs) != 0 {
			t.Errorf("HeldDeletionItemRefs = %v, %v", refs, err)
		}
		if _, err := c.HeldDeletionItemRefs("prov_op", "a%b"); err == nil {
			t.Error("a LIKE wildcard in the fragment was accepted")
		}
		return nil
	})
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.RecordAccountDisableRequest(acct(f.A), "admin-b", nil, now)
	}); err == nil {
		t.Error("B filed a record against A's account")
	}
	inB(t, f, func(c *store.TenantTx) error { return c.RecordAccountDisableRequest(acct(f.B), "admin-b", nil, now) })
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		r, err := c.AccountDisableRequest(acct(f.A))
		if err != nil || r.RequestedBy != "admin-a" || r.RequestedByUser != nil {
			t.Errorf("A's record = %+v, %v", r, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func accountDisableRequestsCovered() map[string]bool {
	return map[string]bool{"RecordAccountDisableRequest": true, "AccountDisableRequest": true, "HeldDeletionItemRefs": true}
}
