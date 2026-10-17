package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The containment credential itself is a row of connection_credentials; its
// isolation tests are in isolation_credentials_test.go.

func seedRetries(t *testing.T, f *storetest.Fixture) map[string]string {
	t.Helper()
	ids := map[string]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		r := &store.ContainmentRetry{IdentityID: tn.IDs["alice"], AccountID: tn.IDs["acct:okta:alice"], System: "okta",
			Account: "alice", Action: "revoke_sessions", Trigger: "leaver", NextAttemptAt: storetest.Now, LastError: "boom"}
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.InsertContainmentRetry(r, storetest.Now)
		}); err != nil {
			t.Fatal(err)
		}
		ids[tn.Slug] = r.ID
	}
	return ids
}

func TestIsolation_ContainmentRetryReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedRetries(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		rs, err := c.ContainmentRetriesFor(f.B.IDs["alice"])
		if err != nil || len(rs) != 1 || rs[0].ID != ids[f.B.Slug] {
			t.Errorf("ContainmentRetriesFor = %v, %v", rs, err)
		}
		if rs, err := c.ContainmentRetriesFor(f.A.IDs["alice"]); err != nil || len(rs) != 0 {
			t.Errorf("ContainmentRetriesFor(A's identity) = %v, %v", rs, err)
		}
		if _, err := c.ContainmentRetry(ids[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ContainmentRetry(A's) = %v", err)
		}
		due, err := c.DueContainmentRetries(storetest.Now)
		if err != nil || len(due) != 1 || due[0].ID != ids[f.B.Slug] {
			t.Errorf("DueContainmentRetries = %v, %v", due, err)
		}
		if _, err := c.OpenContainmentRetry(f.A.IDs["acct:okta:alice"], "revoke_sessions"); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Error(err)
		}
		return nil
	})
}

func TestIsolation_ContainmentRetryWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedRetries(t, f)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.UpdateContainmentRetry(ids[f.A.Slug], "succeeded", 1, storetest.Now, "", storetest.Now)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("update of A's retry in B = %v, want ErrNotFound", err)
	}
	// B names A's identity and account: the guard trigger refuses it
	err = f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertContainmentRetry(&store.ContainmentRetry{IdentityID: f.A.IDs["bob"], AccountID: f.A.IDs["acct:okta:bob"],
			System: "okta", Account: "bob", Action: "revoke_grants", Trigger: "manual", NextAttemptAt: storetest.Now}, storetest.Now)
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("insert naming A's rows = %v, want ErrCrossTenant", err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		r, err := c.ContainmentRetry(ids[f.A.Slug])
		if err != nil || r.Status != "pending" || r.Attempts != 0 {
			t.Errorf("A's retry = %+v, %v", r, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func containmentCovered() map[string]bool {
	return map[string]bool{
		"InsertContainmentRetry": true, "UpdateContainmentRetry": true, // TestIsolation_ContainmentRetryWritesScoped
		"ContainmentRetry": true, "ContainmentRetriesFor": true, "DueContainmentRetries": true,
		"OpenContainmentRetry": true} // TestIsolation_ContainmentRetryReads
}
