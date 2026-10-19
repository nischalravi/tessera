package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestActiveIdentityMatching(t *testing.T) {
	f := storetest.TwoTenants(t)
	email := "  Noor.Achterberg@Larkspur.Example "
	var live int64
	inB(t, f, func(c *store.TenantTx) error {
		var err error
		if live, err = c.InsertIdentity(&store.Identity{ExternalID: "emp-live", Name: "Noor", Email: &email, Type: "human",
			Status: "active", CreatedAt: storetest.Now}); err != nil {
			return err
		}
		gone2 := "former@larkspur.example"
		_, err = c.InsertIdentity(&store.Identity{ExternalID: "emp-gone", Name: "Former", Email: &gone2, Type: "human",
			Status: "terminated", CreatedAt: storetest.Now})
		return err
	})
	tests := []struct {
		name, email, xid string
		want             int64 // 0: ErrNotFound
	}{
		{"email in another case", "noor.achterberg@LARKSPUR.example", "", live},
		{"email with spaces", " noor.achterberg@larkspur.example\t", "", live},
		{"hr id", "", "emp-live", live},
		{"hr id with spaces", "", " emp-live ", live},
		{"email or hr id, lowest id wins", "noor.achterberg@larkspur.example", "emp-gone", live},
		{"terminated email is a rehire", "former@larkspur.example", "", 0},
		{"terminated hr id is a rehire", "", "emp-gone", 0},
		{"unknown", "nobody@larkspur.example", "emp-none", 0},
		{"empty arguments match nothing", "", "", 0},
		{"blank arguments match nothing", "  ", " ", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inB(t, f, func(c *store.TenantTx) error {
				got, err := c.ActiveIdentityMatching(tt.email, tt.xid)
				if tt.want == 0 {
					if !errors.Is(err, store.ErrNotFound) {
						t.Errorf("got %v, %v; want ErrNotFound", got, err)
					}
					return nil
				}
				if err != nil || got.ID != tt.want {
					t.Errorf("got %v, %v; want id %d", got, err, tt.want)
				}
				return nil
			})
		})
	}
	// the same email in tenant A is not a match in B's favour, nor the reverse
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if got, err := c.ActiveIdentityMatching("noor.achterberg@larkspur.example", "emp-live"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant A saw tenant B's identity: %v, %v", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
