package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Sealed connection credentials (#220): a tenant sees and changes only its own
// rows, for both purposes; another tenant's connection id looks nonexistent,
// and a row naming it is refused by the guard trigger.

func seedCredentials(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.PutCredential(&store.Credential{ConnectionID: tn.Refs["connection"], Purpose: store.PurposeContainment,
				Sealed: []byte("sealed-" + tn.Slug), BaseURL: "https://" + tn.Slug + ".okta.com", UpdatedBy: "admin",
				UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			return c.PutCredential(&store.Credential{ConnectionID: tn.Refs["connection"], Purpose: store.PurposeBind,
				Ref: "sealed:shared", Sealed: []byte("bind-" + tn.Slug + "-" + storetest.ReadinessSentinel), UpdatedBy: "admin",
				UpdatedAt: storetest.Now})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsolation_ConnectionCredentials(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedCredentials(t, f)
	conn := func(tn storetest.Tenant) string { return tn.Refs["connection"] }
	inB(t, f, func(c *store.TenantTx) error {
		ks, err := c.Credentials(store.PurposeContainment)
		if err != nil || len(ks) != 1 || ks[0].ConnectionID != conn(f.B) || string(ks[0].Sealed) != "sealed-"+f.B.Slug {
			t.Errorf("Credentials(containment) = %v, %v", ks, err)
		}
		if ks, err := c.Credentials(store.PurposeBind); err != nil || len(ks) != 1 || ks[0].ConnectionID != conn(f.B) {
			t.Errorf("Credentials(bind) = %v, %v", ks, err)
		}
		// A's connection id, under either purpose, reads as missing.
		if _, err := c.Credential(conn(f.A), store.PurposeContainment, ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Credential(A's connection, containment) = %v", err)
		}
		if _, err := c.Credential(conn(f.A), store.PurposeBind, "sealed:shared"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Credential(A's connection, bind) = %v", err)
		}
		// B cannot delete A's rows.
		if err := c.DeleteCredential(conn(f.A), store.PurposeContainment, ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteCredential(A's connection) = %v", err)
		}
		return nil
	})
	// B naming A's connection is refused by the guard trigger.
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.PutCredential(&store.Credential{ConnectionID: conn(f.A), Purpose: store.PurposeContainment,
			Sealed: []byte("evil"), UpdatedBy: "b", UpdatedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Fatalf("B writing A's connection = %v, want ErrCrossTenant", err)
	}
	// A replaces and deletes its own rows; B's stay.
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if err := c.PutCredential(&store.Credential{ConnectionID: conn(f.A), Purpose: store.PurposeBind, Ref: "sealed:shared",
			Sealed: []byte("bind-A-2"), UpdatedBy: "a", UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.DeleteCredential(conn(f.A), store.PurposeContainment, "")
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		k, err := c.Credential(conn(f.A), store.PurposeBind, "sealed:shared")
		if err != nil || string(k.Sealed) != "bind-A-2" {
			t.Errorf("A's replaced credential = %v, %v", k, err)
		}
		if _, err := c.Credential(conn(f.A), store.PurposeContainment, ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("A's deleted credential = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		k, err := c.Credential(conn(f.B), store.PurposeContainment, "")
		if err != nil || string(k.Sealed) != "sealed-"+f.B.Slug {
			t.Errorf("B's containment after A's writes = %v, %v", k, err)
		}
		k, err = c.Credential(conn(f.B), store.PurposeBind, "sealed:shared")
		if err != nil || !bytes.Contains(k.Sealed, []byte("bind-"+f.B.Slug)) {
			t.Errorf("B's bind after A's writes = %v, %v", k, err)
		}
		return nil
	})
	// A read-only transaction cannot write.
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if err := c.PutCredential(&store.Credential{ConnectionID: conn(f.A), Purpose: store.PurposeBind, Ref: "sealed:x",
			Sealed: []byte("x"), UpdatedBy: "a", UpdatedAt: storetest.Now}); !errors.Is(err, store.ErrReadOnly) {
			t.Errorf("write in a read transaction: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// DeleteOrphanBindCredential and DeleteBindCredentials (#838): they act on the caller's tenant only, and the
// orphan delete keeps a row a revision of the connection still references.
func TestIsolation_DeleteBindCredentials(t *testing.T) {
	f := storetest.TwoTenants(t)
	conn := func(tn storetest.Tenant) string { return tn.Refs["connection:ad"] }
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.PutCredential(&store.Credential{ConnectionID: conn(tn), Purpose: store.PurposeBind, Ref: "sealed:shared",
				Sealed: []byte("bind-" + tn.Slug), UpdatedBy: "admin", UpdatedAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
	}
	has := func(tn storetest.Tenant) bool {
		found := false
		if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			_, err := c.Credential(conn(tn), store.PurposeBind, "sealed:shared")
			found = err == nil
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return found
	}
	// B naming A's connection removes nothing of A's.
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.DeleteOrphanBindCredential(conn(f.A), "sealed:shared"); err != nil {
			t.Error(err)
		}
		return c.DeleteBindCredentials(conn(f.A))
	})
	if !has(f.A) || !has(f.B) {
		t.Fatal("a cross-tenant delete removed a row")
	}
	// A revision still referencing the ref keeps the row.
	rev := f.A.Refs["revision:ad"]
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		r, err := c.Revision(rev)
		if err != nil {
			return err
		}
		if err := c.UpdateRevisionSecret(rev, "sealed:shared", "v1", r.ConfigHash, storetest.Now); err != nil {
			return err
		}
		return c.DeleteOrphanBindCredential(conn(f.A), "sealed:shared")
	}); err != nil {
		t.Fatal(err)
	}
	if !has(f.A) {
		t.Fatal("a referenced row was deleted")
	}
	// Once the reference is cleared the row goes; B's stays.
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		r, err := c.Revision(rev)
		if err != nil {
			return err
		}
		if err := c.ClearRevisionSecret(rev, r.ConfigHash, storetest.Now); err != nil {
			return err
		}
		return c.DeleteOrphanBindCredential(conn(f.A), "sealed:shared")
	}); err != nil {
		t.Fatal(err)
	}
	if has(f.A) || !has(f.B) {
		t.Fatalf("after the orphan delete: A has = %v, B has = %v", has(f.A), has(f.B))
	}
}
