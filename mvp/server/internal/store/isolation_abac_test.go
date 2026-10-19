package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Attribute policy isolation (issue #162): a tenant sees and changes only its
// own policies, versions and bindings; rows naming another tenant's ids are
// refused by the guard triggers.

type abacRows struct {
	user   *store.PlatformUser
	policy string
	item   string
	group  int64
}

func seedAbacRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) abacRows {
	t.Helper()
	r := abacRows{policy: "pol-" + tag, item: "item-" + tag, group: tn.IDs["group:okta:eng"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.user = &store.PlatformUser{DisplayName: "policy admin " + tag, CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		uid := r.user.ID.String()
		if err := c.InsertAbacPolicy(&store.AbacPolicy{ID: r.policy, Name: "Finance " + tag,
			Condition: `{"attr":"identity.department","op":"eq","value":"Finance"}`, Status: store.AbacActive, Version: 1,
			CreatedAt: storetest.Now, UpdatedBy: &uid, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.AddAbacPolicyVersion(&store.AbacPolicyVersion{PolicyID: r.policy, Version: 1, Snapshot: "{}",
			ChangedBy: &uid, Actor: "x", ChangedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.PutCatalogItem(&store.CatalogItem{ID: r.item, GroupID: r.group, Requestable: true, Risk: "low",
			UpdatedBy: &uid, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.PutAbacBinding(&store.AbacBinding{Kind: store.BindCatalogItem, TargetID: r.item, PolicyID: r.policy,
			BoundBy: &uid, BoundAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func abacFixture(t *testing.T) (*storetest.Fixture, abacRows, abacRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedAbacRows(t, f.DB, f.A, "a"), seedAbacRows(t, f.DB, f.B, "b")
}

func TestIsolation_AbacReads(t *testing.T) {
	f, a, b := abacFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if ps, err := c.AbacPolicies(); err != nil || len(ps) != 1 || ps[0].ID != b.policy {
			t.Errorf("AbacPolicies = %v, %v", ps, err)
		}
		if _, err := c.AbacPolicy(a.policy); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AbacPolicy(A's) = %v", err)
		}
		if _, err := c.AbacPolicyByName("Finance a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AbacPolicyByName(A's) = %v", err)
		}
		if vs, err := c.AbacPolicyVersions(a.policy); err != nil || len(vs) != 0 {
			t.Errorf("AbacPolicyVersions(A's) = %v, %v", vs, err)
		}
		if bs, err := c.AbacBindings(); err != nil || len(bs) != 1 || bs[0].PolicyID != b.policy {
			t.Errorf("AbacBindings = %v, %v", bs, err)
		}
		if _, err := c.AbacBinding(store.BindCatalogItem, a.item); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AbacBinding(A's) = %v", err)
		}
		return nil
	})
}

var abacMutations = map[string]func(c *store.TenantTx, a, b abacRows) error{
	"InsertAbacPolicy": func(c *store.TenantTx, a, _ abacRows) error {
		uid := a.user.ID.String() // A's user in B's policy
		return c.InsertAbacPolicy(&store.AbacPolicy{ID: "x", Name: "x", Condition: "{}", Status: store.AbacActive, Version: 1,
			CreatedAt: storetest.Now, UpdatedBy: &uid, UpdatedAt: storetest.Now})
	},
	"SaveAbacPolicy": func(c *store.TenantTx, a, _ abacRows) error {
		return c.SaveAbacPolicy(&store.AbacPolicy{ID: a.policy, Name: "taken", Condition: "{}", Status: store.AbacRetired,
			Version: 2, UpdatedAt: storetest.Now}, 1)
	},
	"AddAbacPolicyVersion": func(c *store.TenantTx, a, _ abacRows) error {
		return c.AddAbacPolicyVersion(&store.AbacPolicyVersion{PolicyID: a.policy, Version: 9, Snapshot: "{}", Actor: "x",
			ChangedAt: storetest.Now})
	},
	"PutAbacBinding": func(c *store.TenantTx, a, b abacRows) error {
		return c.PutAbacBinding(&store.AbacBinding{Kind: store.BindCatalogItem, TargetID: b.item, PolicyID: a.policy,
			BoundAt: storetest.Now})
	},
	"PutAbacBinding(A's item)": func(c *store.TenantTx, a, b abacRows) error {
		return c.PutAbacBinding(&store.AbacBinding{Kind: store.BindCatalogItem, TargetID: a.item, PolicyID: b.policy,
			BoundAt: storetest.Now})
	},
	"DeleteAbacBinding": func(c *store.TenantTx, a, _ abacRows) error {
		if err := c.DeleteAbacBinding(store.BindCatalogItem, a.item); err != nil {
			return err
		}
		return store.ErrNotFound // nothing to delete in B; A's dump proves the binding stayed
	},
}

func TestIsolation_AbacMutationsScoped(t *testing.T) {
	for name, fn := range abacMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := abacFixture(t)
			before := abacDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if err == nil {
				t.Fatalf("%s across tenants succeeded", name)
			}
			if after := abacDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func TestAbac_VersionsAppendOnlyAndStaleSave(t *testing.T) {
	f, a, _ := abacFixture(t)
	ctx := context.Background()
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.SaveAbacPolicy(&store.AbacPolicy{ID: a.policy, Name: "x", Condition: "{}", Status: store.AbacActive,
			Version: 3, UpdatedAt: storetest.Now}, 2)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SaveAbacPolicy at a stale version = %v, want ErrNotFound", err)
	}
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.AddAbacPolicyVersion(&store.AbacPolicyVersion{PolicyID: a.policy, Version: 1, Snapshot: "{}", Actor: "x",
			ChangedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a duplicate version was accepted")
	}
}

func abacDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		ps, err := c.AbacPolicies()
		if err != nil {
			return err
		}
		var vs []*store.AbacPolicyVersion
		for _, p := range ps {
			v, err := c.AbacPolicyVersions(p.ID)
			if err != nil {
				return err
			}
			vs = append(vs, v...)
		}
		bs, err := c.AbacBindings()
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{ps, vs, bs})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func abacCovered() map[string]bool {
	out := map[string]bool{}
	for k := range abacMutations {
		out[k] = true
	}
	for _, k := range []string{"AbacPolicies", "AbacPolicy", "AbacPolicyByName", "AbacPolicyVersions", "AbacBindings",
		"AbacBinding"} {
		out[k] = true // TestIsolation_AbacReads
	}
	return out
}
