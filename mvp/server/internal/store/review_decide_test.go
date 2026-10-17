package store_test

import (
	"context"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// DecideItem writes a decision once: the update is conditional on the item
// being undecided, so a second writer (or a replay) changes nothing.
func TestDecideItemIsConditional(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	item := f.A.IDs["item"]
	by := store.UserRef{Display: "reviewer"}
	comment := "first"

	attempts := []struct {
		decision string
		comment  *string
		applied  bool
	}{
		{"revoke", &comment, true},
		{"keep", nil, false},
		{"revoke", nil, false},
	}
	for i, a := range attempts {
		err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
			ok, err := c.DecideItem(item, a.decision, a.comment, storetest.Now, by)
			if err == nil && ok != a.applied {
				t.Errorf("attempt %d (%s): applied = %v, want %v", i, a.decision, ok, a.applied)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		it, err := c.Item(item)
		if err != nil {
			return err
		}
		if it.Decision == nil || *it.Decision != "revoke" || it.Comment == nil || *it.Comment != "first" {
			t.Errorf("item = %v / %v, want the first decision kept", it.Decision, it.Comment)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// An item of another tenant is not decided (and reports applied = false).
func TestDecideItemOtherTenantNotApplied(t *testing.T) {
	f := storetest.TwoTenants(t)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		ok, err := c.DecideItem(f.B.IDs["item"], "keep", nil, storetest.Now, store.UserRef{})
		if ok {
			t.Error("decided another tenant's item")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
