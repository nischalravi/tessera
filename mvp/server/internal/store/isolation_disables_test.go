package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Identity disable records (schema/0310): a tenant sees and changes only its
// own; another tenant's identity or account id looks nonexistent, and a row
// naming one is refused by the guard triggers.

func seedDisables(t *testing.T, f *storetest.Fixture) map[string]string {
	t.Helper()
	ids := map[string]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		d := &store.IdentityDisable{IdentityID: tn.IDs["alice"], Reason: "r " + tn.Slug, DisabledBy: "pa", DisabledAt: storetest.Now,
			ContainmentStatus: "done", AccountIDs: []int64{tn.IDs["acct:okta:alice"]}}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error { return c.InsertIdentityDisable(d) })
		if err != nil {
			t.Fatal(err)
		}
		ids[tn.Slug] = d.ID
	}
	return ids
}

func TestIsolation_IdentityDisableReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedDisables(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		d, err := c.OpenIdentityDisable(f.B.IDs["alice"])
		if err != nil || d.Reason != "r "+f.B.Slug || len(d.AccountIDs) != 1 || d.AccountIDs[0] != f.B.IDs["acct:okta:alice"] {
			t.Errorf("OpenIdentityDisable = %+v, %v", d, err)
		}
		if _, err := c.OpenIdentityDisable(f.A.IDs["alice"]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OpenIdentityDisable(A's identity) = %v", err)
		}
		if ds, err := c.IdentityDisables(f.A.IDs["alice"]); err != nil || len(ds) != 0 {
			t.Errorf("IdentityDisables(A's identity) = %v, %v", ds, err)
		}
		return nil
	})
}

func TestIsolation_IdentityDisableMutationsScoped(t *testing.T) {
	muts := map[string]func(c *store.TenantTx, a, b storetest.Tenant, aID string) error{
		"CloseIdentityDisable": func(c *store.TenantTx, _, _ storetest.Tenant, aID string) error {
			return c.CloseIdentityDisable(aID, "b", "x", storetest.Now)
		},
		"SetIdentityStatusFrom": func(c *store.TenantTx, a, _ storetest.Tenant, _ string) error {
			return c.SetIdentityStatusFrom(a.IDs["alice"], "active", "disabled")
		},
		"EnableAccount": func(c *store.TenantTx, a, _ storetest.Tenant, _ string) error {
			ok, err := c.EnableAccount(a.IDs["acct:okta:alice"])
			if err == nil && !ok {
				return store.ErrNotFound
			}
			return err
		},
		"InsertIdentityDisable": func(c *store.TenantTx, a, _ storetest.Tenant, _ string) error {
			return c.InsertIdentityDisable(&store.IdentityDisable{IdentityID: a.IDs["bob"], Reason: "x", DisabledBy: "b", DisabledAt: storetest.Now})
		},
		"InsertIdentityDisable/account": func(c *store.TenantTx, a, b storetest.Tenant, _ string) error {
			return c.InsertIdentityDisable(&store.IdentityDisable{IdentityID: b.IDs["bob"], Reason: "x", DisabledBy: "b", DisabledAt: storetest.Now,
				AccountIDs: []int64{a.IDs["acct:okta:alice"]}})
		},
	}
	for name, fn := range muts {
		t.Run(name, func(t *testing.T) {
			f := storetest.TwoTenants(t)
			// A's account is disabled so EnableAccount would visibly change it
			if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error { return c.DisableAccount(f.A.IDs["acct:okta:alice"]) }); err != nil {
				t.Fatal(err)
			}
			ids := seedDisables(t, f)
			before := disableDump(t, f)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, f.A, f.B, ids[f.A.Slug]) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := disableDump(t, f); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func TestIdentityDisable_OneOpenPerIdentity(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedDisables(t, f)
	id := f.A.IDs["alice"]
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if err := c.InsertIdentityDisable(&store.IdentityDisable{IdentityID: id, Reason: "again", DisabledBy: "pa", DisabledAt: storetest.Now}); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("second open disable = %v, want ErrDuplicate", err)
		}
		d, err := c.OpenIdentityDisable(id)
		if err != nil {
			return err
		}
		if err := c.CloseIdentityDisable(d.ID, "pa", "ok", storetest.Now.Add(time.Hour)); err != nil {
			return err
		}
		if err := c.CloseIdentityDisable(d.ID, "pa", "ok", storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("closing twice = %v, want ErrNotFound", err)
		}
		// a closed one does not collide with a new Disable, and history keeps both
		if err := c.InsertIdentityDisable(&store.IdentityDisable{IdentityID: id, Reason: "again", DisabledBy: "pa", DisabledAt: storetest.Now.Add(2 * time.Hour)}); err != nil {
			t.Errorf("disable after enable = %v", err)
		}
		if ds, err := c.IdentityDisables(id); err != nil || len(ds) != 2 || ds[1].EnabledAt == nil || ds[0].EnabledAt != nil {
			t.Errorf("history = %+v, %v", ds, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func disableDump(t *testing.T, f *storetest.Fixture) string {
	t.Helper()
	out := storetest.Dump(t, f.DB, f.A.ID)
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		ds, err := c.IdentityDisables(f.A.IDs["alice"])
		if err != nil {
			return err
		}
		b, err := json.Marshal(ds)
		out += "\n" + string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func disablesCovered() map[string]bool {
	return map[string]bool{"InsertIdentityDisable": true, "OpenIdentityDisable": true, "IdentityDisables": true,
		"CloseIdentityDisable": true, "SetIdentityStatusFrom": true, "EnableAccount": true}
}
