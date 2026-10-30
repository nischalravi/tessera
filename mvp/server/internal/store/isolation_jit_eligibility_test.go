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

// JIT eligibility isolation (issue #651, AC-5): a tenant sees and changes only its own settings, rules, the groups
// they name and their versions; another tenant's ids look nonexistent and rows naming them are refused.

type jitRows struct {
	id    string
	group int64
	other int64
}

func seedJITRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) jitRows {
	t.Helper()
	r := jitRows{id: "jit-" + tag, group: tn.IDs["group:okta:eng"], other: tn.IDs["group:okta:payments-clerks"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		if err := c.PutJITSettings(true, "seed "+tag, storetest.Now); err != nil {
			return err
		}
		if err := c.InsertJITEligibility(&store.JITEligibility{ID: r.id, Key: "prod-" + tag, Status: store.JITEligibilityActive,
			MaxHours: 4, MinApprovals: 1, StepUp: true, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.SetJITEligibilityGroups(r.id, store.JITPrincipal, []int64{r.group}); err != nil {
			return err
		}
		if err := c.SetJITEligibilityGroups(r.id, store.JITEntitlement, []int64{r.other}); err != nil {
			return err
		}
		ref := `{"commit":"c-` + tag + `"}`
		return c.AddJITEligibilityVersion(&store.JITEligibilityVersion{EligibilityID: r.id, Version: 1, Snapshot: "{}",
			Actor: "x", ChangedAt: storetest.Now, PolicyRef: &ref})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func jitFixture(t *testing.T) (*storetest.Fixture, jitRows, jitRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedJITRows(t, f.DB, f.A, "a"), seedJITRows(t, f.DB, f.B, "b")
}

func TestIsolation_JITEligibilityReads(t *testing.T) {
	f, a, b := jitFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if s, err := c.JITSettings(); err != nil || !s.Enabled || s.UpdatedBy != "seed b" {
			t.Errorf("JITSettings = %v, %v; want B's", s, err)
		}
		es, err := c.JITEligibilities()
		if err != nil || len(es) != 1 || es[0].ID != b.id || len(es[0].Principals) != 1 || es[0].Principals[0] != b.group ||
			len(es[0].Entitlements) != 1 || !es[0].StepUp || es[0].MaxHours != 4 {
			t.Errorf("JITEligibilities = %+v, %v; want only B's", es, err)
		}
		if _, err := c.JITEligibilityByKey("prod-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("JITEligibilityByKey(A's) = %v", err)
		}
		if vs, err := c.JITEligibilityVersions(a.id); err != nil || len(vs) != 0 {
			t.Errorf("JITEligibilityVersions(A's) = %v, %v", vs, err)
		}
		if vs, err := c.JITEligibilityVersions(b.id); err != nil || len(vs) != 1 || vs[0].PolicyRef == nil || *vs[0].PolicyRef != `{"commit":"c-b"}` {
			t.Errorf("JITEligibilityVersions(B's) = %v, %v", vs, err)
		}
		return nil
	})
}

// jitMutations change one of A's rows (or point B's at A's); run in B they fail and leave A alone.
var jitMutations = map[string]func(c *store.TenantTx, a, b jitRows) error{
	"SaveJITEligibility": func(c *store.TenantTx, a, _ jitRows) error {
		return c.SaveJITEligibility(&store.JITEligibility{ID: a.id, Status: store.JITEligibilityRetired, MaxHours: 1,
			Version: 2, UpdatedAt: storetest.Now}, 1)
	},
	"SetJITEligibilityGroups(A's group)": func(c *store.TenantTx, a, b jitRows) error {
		return c.SetJITEligibilityGroups(b.id, store.JITApprover, []int64{a.group})
	},
	"SetJITEligibilityGroups(A's rule)": func(c *store.TenantTx, a, b jitRows) error {
		return c.SetJITEligibilityGroups(a.id, store.JITApprover, []int64{b.group})
	},
	"AddJITEligibilityVersion": func(c *store.TenantTx, a, _ jitRows) error {
		return c.AddJITEligibilityVersion(&store.JITEligibilityVersion{EligibilityID: a.id, Version: 9, Snapshot: "{}",
			Actor: "x", ChangedAt: storetest.Now})
	},
}

func TestIsolation_JITEligibilityMutationsScoped(t *testing.T) {
	for name, fn := range jitMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := jitFixture(t)
			before := jitDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if err == nil {
				t.Fatalf("%s across tenants succeeded", name)
			}
			if after := jitDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func TestJITEligibility_SettingsVersionsAndKeys(t *testing.T) {
	f, a, _ := jitFixture(t)
	ctx := context.Background()
	// a tenant that never applied eligibility has enforcement off
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.PutJITSettings(false, "x", storetest.Now); err != nil {
			return err
		}
		s, err := c.JITSettings()
		if err != nil || s.Enabled {
			t.Errorf("JITSettings after off = %v, %v", s, err)
		}
		// the key is unique per tenant
		return c.InsertJITEligibility(&store.JITEligibility{Key: "prod-a", Status: store.JITEligibilityActive, MaxHours: 1,
			Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("a repeated key = %v, want ErrDuplicate", err)
	}
	// a stale version does not save
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.SaveJITEligibility(&store.JITEligibility{ID: a.id, Status: store.JITEligibilityActive, MaxHours: 2,
			Version: 3, UpdatedAt: storetest.Now}, 2)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SaveJITEligibility at a stale version = %v, want ErrNotFound", err)
	}
	// versions are append-only and unique per rule
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.AddJITEligibilityVersion(&store.JITEligibilityVersion{EligibilityID: a.id, Version: 1, Snapshot: "{}",
			Actor: "x", ChangedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a duplicate version was accepted")
	}
}

func jitDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		s, err := c.JITSettings()
		if err != nil {
			return err
		}
		es, err := c.JITEligibilities()
		if err != nil {
			return err
		}
		var vs []*store.JITEligibilityVersion
		for _, e := range es {
			v, err := c.JITEligibilityVersions(e.ID)
			if err != nil {
				return err
			}
			vs = append(vs, v...)
		}
		b, err := json.Marshal([]any{s, es, vs})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func jitEligibilityCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"SaveJITEligibility", "SetJITEligibilityGroups", "AddJITEligibilityVersion"} {
		out[k] = true // TestIsolation_JITEligibilityMutationsScoped
	}
	for _, k := range []string{"JITSettings", "JITEligibilities", "JITEligibilityByKey", "JITEligibilityVersions"} {
		out[k] = true // TestIsolation_JITEligibilityReads
	}
	for _, k := range []string{"PutJITSettings", "InsertJITEligibility"} {
		out[k] = true // the seed of both tenants, and TestJITEligibility_SettingsVersionsAndKeys
	}
	return out
}
