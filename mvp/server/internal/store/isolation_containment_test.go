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

func containmentCovered() map[string]bool {
	return map[string]bool{"ContainmentCredential": true, "ContainmentCredentials": true, // TestIsolation_ContainmentCredentialReads
		"PutContainmentCredential": true} // TestIsolation_ContainmentCredentialWriteScoped
}
