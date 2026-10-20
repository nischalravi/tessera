package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Ownership isolation (issue #167): a tenant sees and changes only its own
// ownership rows, and cannot name another tenant's people or groups.

func seedOwnership(t *testing.T, db *store.DB, tn storetest.Tenant) string {
	t.Helper()
	key := fmt.Sprint(tn.IDs["group:okta:eng"])
	carol, bob := tn.IDs["carol"], tn.IDs["bob"]
	if err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		return c.PutOwnership(&store.Ownership{Kind: store.OwnedGroup, Key: key, PrimaryID: &carol, BackupID: &bob,
			Purpose: "engineering", UpdatedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestIsolation_OwnershipRows(t *testing.T) {
	f := storetest.TwoTenants(t)
	ka, kb := seedOwnership(t, f.DB, f.A), seedOwnership(t, f.DB, f.B)
	inB(t, f, func(c *store.TenantTx) error {
		if os, err := c.Ownerships(""); err != nil || len(os) != 1 || os[0].Key != kb {
			t.Errorf("Ownerships = %v, %v", os, err)
		}
		if ka != kb {
			if _, err := c.Ownership(store.OwnedGroup, ka); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Ownership(A's key) = %v", err)
			}
		}
		if os, err := c.OwnershipsOf(f.A.IDs["carol"]); err != nil || len(os) != 0 {
			t.Errorf("OwnershipsOf(A's carol) = %v, %v", os, err)
		}
		return nil
	})
	// B's row naming A's people or group is refused
	before := ownDump(t, f.DB, f.A.ID)
	for name, o := range map[string]store.Ownership{
		"primary": {PrimaryID: ptr(f.A.IDs["carol"])}, "backup": {BackupID: ptr(f.A.IDs["bob"])},
		"group": {GroupID: ptr(f.A.IDs["group:okta:eng"])},
	} {
		o.Kind, o.Key, o.UpdatedAt = store.OwnedApp, "okta", storetest.Now
		err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return c.PutOwnership(&o) })
		if !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("%s: %v, want ErrCrossTenant", name, err)
		}
	}
	if ownDump(t, f.DB, f.A.ID) != before {
		t.Error("B's writes changed A")
	}
}

func ptr(v int64) *int64 { return &v }

func ownDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		os, err := c.Ownerships("")
		if err != nil {
			return err
		}
		b, err := json.Marshal(os)
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func ownershipCovered() map[string]bool {
	return map[string]bool{"Ownerships": true, "Ownership": true, "OwnershipsOf": true, "PutOwnership": true}
}
