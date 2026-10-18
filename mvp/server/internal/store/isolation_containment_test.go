package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Containment credentials (issue #106): a tenant sees and changes only its
// own sealed provider credentials; another tenant's connection id looks
// nonexistent, and a row naming it is refused by the guard trigger.

func seedContainment(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.PutContainmentCredential(&store.ContainmentCredential{ConnectionID: tn.Refs["connection"],
				BaseURL: "https://" + tn.Slug + ".okta.com", TokenEnc: []byte("sealed-" + tn.Slug), UpdatedBy: "admin",
				UpdatedAt: storetest.Now})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsolation_ContainmentCredentialReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedContainment(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		ks, err := c.ContainmentCredentials()
		if err != nil || len(ks) != 1 || ks[0].ConnectionID != f.B.Refs["connection"] || string(ks[0].TokenEnc) != "sealed-"+f.B.Slug {
			t.Errorf("ContainmentCredentials = %v, %v", ks, err)
		}
		if _, err := c.ContainmentCredential(f.A.Refs["connection"]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ContainmentCredential(A's connection) = %v", err)
		}
		return nil
	})
}

func TestIsolation_ContainmentCredentialWriteScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedContainment(t, f)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		// B names A's connection: the guard trigger refuses it
		return c.PutContainmentCredential(&store.ContainmentCredential{ConnectionID: f.A.Refs["connection"],
			BaseURL: "https://evil.example", TokenEnc: []byte("evil"), UpdatedBy: "b", UpdatedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Fatalf("B writing A's connection = %v, want ErrCrossTenant", err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		k, err := c.ContainmentCredential(f.A.Refs["connection"])
		if err != nil || string(k.TokenEnc) != "sealed-"+f.A.Slug {
			t.Errorf("A's credential = %v, %v", k, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

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
	return map[string]bool{"ContainmentCredential": true, "ContainmentCredentials": true, // TestIsolation_ContainmentCredentialReads
		"PutContainmentCredential": true,                                 // TestIsolation_ContainmentCredentialWriteScoped
		"InsertContainmentRetry":   true, "UpdateContainmentRetry": true, // TestIsolation_ContainmentRetryWritesScoped
		"ContainmentRetry": true, "ContainmentRetriesFor": true, "DueContainmentRetries": true,
		"OpenContainmentRetry": true} // TestIsolation_ContainmentRetryReads
}
