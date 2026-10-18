package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestIsolation_ConnectionSecrets: sealed connection credentials are scoped
// to the tenant. Tenant B holds a row under the same reference as tenant A
// and a row only it has; reads and replacement in A never see or touch B's.
func TestIsolation_ConnectionSecrets(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	put := func(id string, tn storetest.Tenant, ref string, blob []byte) {
		t.Helper()
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			return c.PutConnectionSecret(ref, blob, storetest.Now)
		}); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	a, b := []byte("sealed-A-blob"), []byte("sealed-B-blob-"+storetest.ReadinessSentinel)
	put("A shared", f.A, "sealed:shared", a)
	put("B shared", f.B, "sealed:shared", b)
	put("B only", f.B, "sealed:b-only", b)

	inA(t, f, func(c *store.TenantTx) error {
		got, err := c.ConnectionSecret("sealed:shared")
		if err != nil || !bytes.Equal(got, a) {
			t.Errorf("A's shared ref: %q %v", got, err)
		}
		if got, err := c.ConnectionSecret("sealed:b-only"); !errors.Is(err, store.ErrNotFound) || got != nil {
			t.Errorf("B's ref read as A: %q %v", got, err)
		}
		return nil
	})
	// Replacing a row in A leaves B's rows alone.
	put("A replace", f.A, "sealed:shared", []byte("sealed-A-blob-2"))
	if err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		for _, ref := range []string{"sealed:shared", "sealed:b-only"} {
			got, err := c.ConnectionSecret(ref)
			if err != nil || !bytes.Equal(got, b) {
				t.Errorf("B's %s after A's writes: %q %v", ref, got, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A read-only transaction cannot write.
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.PutConnectionSecret("sealed:x", a, storetest.Now); !errors.Is(err, store.ErrReadOnly) {
			t.Errorf("write in a read transaction: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
