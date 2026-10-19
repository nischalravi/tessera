package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Identity lifecycle isolation (issue #159): a tenant sees and changes only
// its own lifecycle rows and history; another tenant's identities look
// nonexistent and rows naming them are refused by the guard triggers.

type lcRows struct {
	alice, carol int64
}

func seedLcRows(t *testing.T, db *store.DB, tn storetest.Tenant) lcRows {
	t.Helper()
	r := lcRows{alice: tn.IDs["alice"], carol: tn.IDs["carol"]}
	ends := storetest.Now.Add(48 * time.Hour)
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		if err := c.PutLifecycle(&store.Lifecycle{IdentityID: r.alice, WorkerType: store.WorkerContractor, SponsorID: &r.carol,
			EndsAt: &ends, Source: "manual", UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.AddLifecycleEvent(&store.LifecycleEvent{IdentityID: r.alice, Event: "set", Actor: "x", At: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func lcFixture(t *testing.T) (*storetest.Fixture, lcRows, lcRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedLcRows(t, f.DB, f.A), seedLcRows(t, f.DB, f.B)
}

func TestIsolation_LifecycleReads(t *testing.T) {
	f, a, b := lcFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if ls, err := c.Lifecycles(); err != nil || len(ls) != 1 || ls[0].IdentityID != b.alice {
			t.Errorf("Lifecycles = %v, %v", ls, err)
		}
		if _, err := c.LifecycleFor(a.alice); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("LifecycleFor(A's) = %v", err)
		}
		if ls, err := c.LifecyclesEndingBy(storetest.Now.Add(72 * time.Hour)); err != nil || len(ls) != 1 || ls[0].IdentityID != b.alice {
			t.Errorf("LifecyclesEndingBy = %v, %v", ls, err)
		}
		if evs, err := c.LifecycleEvents(a.alice); err != nil || len(evs) != 0 {
			t.Errorf("LifecycleEvents(A's) = %v, %v", evs, err)
		}
		return nil
	})
}

var lcMutations = map[string]func(c *store.TenantTx, a, b lcRows) error{
	"PutLifecycle": func(c *store.TenantTx, a, _ lcRows) error {
		return c.PutLifecycle(&store.Lifecycle{IdentityID: a.alice, WorkerType: store.WorkerEmployee, Source: "manual", UpdatedAt: storetest.Now})
	},
	"PutLifecycle(A's sponsor)": func(c *store.TenantTx, a, b lcRows) error {
		ends := storetest.Now.Add(time.Hour)
		return c.PutLifecycle(&store.Lifecycle{IdentityID: b.carol, WorkerType: store.WorkerVendor, SponsorID: &a.carol,
			EndsAt: &ends, Source: "manual", UpdatedAt: storetest.Now})
	},
	"MarkLifecycleWarned": func(c *store.TenantTx, a, _ lcRows) error {
		if err := c.MarkLifecycleWarned(a.alice, 1); err != nil {
			return err
		}
		return store.ErrNotFound // nothing to update in B; A's dump proves the row stayed
	},
	"MarkLifecycleEnded": func(c *store.TenantTx, a, _ lcRows) error {
		return c.MarkLifecycleEnded(a.alice, storetest.Now)
	},
	"AddLifecycleEvent": func(c *store.TenantTx, a, _ lcRows) error {
		return c.AddLifecycleEvent(&store.LifecycleEvent{IdentityID: a.alice, Event: "ended", Actor: "x", At: storetest.Now})
	},
}

func TestIsolation_LifecycleMutationsScoped(t *testing.T) {
	for name, fn := range lcMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := lcFixture(t)
			before := lcDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if err == nil {
				t.Fatalf("%s across tenants succeeded", name)
			}
			if after := lcDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func TestLifecycle_RulesAndAppendOnly(t *testing.T) {
	f, a, _ := lcFixture(t)
	ctx := context.Background()
	// a contractor without an end date is refused by the schema
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.PutLifecycle(&store.Lifecycle{IdentityID: a.carol, WorkerType: store.WorkerContractor, Source: "manual", UpdatedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a contractor without an end date was accepted")
	}
	// ending twice reports ErrNotFound
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.MarkLifecycleEnded(a.alice, storetest.Now); err != nil {
			return err
		}
		if err := c.MarkLifecycleEnded(a.alice, storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second end = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func lcDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		ls, err := c.Lifecycles()
		if err != nil {
			return err
		}
		var evs []*store.LifecycleEvent
		for _, l := range ls {
			e, err := c.LifecycleEvents(l.IdentityID)
			if err != nil {
				return err
			}
			evs = append(evs, e...)
		}
		b, err := json.Marshal([]any{ls, evs})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func lifecycleCovered() map[string]bool {
	out := map[string]bool{}
	for k := range lcMutations {
		out[k] = true
	}
	for _, k := range []string{"Lifecycles", "LifecycleFor", "LifecyclesEndingBy", "LifecycleEvents"} {
		out[k] = true // TestIsolation_LifecycleReads
	}
	return out
}
