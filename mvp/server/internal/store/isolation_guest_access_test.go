package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Guest access isolation (issue #75): a tenant sees and changes only its own
// bundle items, recorded assurance and catalog populations; another tenant's
// id looks nonexistent, and a row naming another tenant's sponsorship,
// person, group or catalog item is refused by the guard triggers.

type gaRows struct {
	spRows
	item, catalogItem string
	group             int64
	edge              int64
}

func seedGuestAccess(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) gaRows {
	t.Helper()
	r := gaRows{spRows: seedSponsorship(t, db, tn, tag), item: "bi-" + tag, catalogItem: "gitem-" + tag, group: tn.IDs["group:okta:payments-clerks"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		if err := c.PutCatalogItem(&store.CatalogItem{ID: r.catalogItem, GroupID: r.group, Requestable: true, Risk: "low",
			UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.SetCatalogPopulations(r.catalogItem, []string{store.PopVisitor}); err != nil {
			return err
		}
		if err := c.PutIdentityAssurance(&store.Assurance{IdentityID: r.guest, IAL: 1, AAL: 1, Source: "claim " + tag, RecordedAt: storetest.Now}); err != nil {
			return err
		}
		var err error
		if r.edge, err = c.InsertEdge(&store.GrantEdge{Src: key("account", tn.IDs["acct:okta:alice"]), Dst: key("group", r.group),
			Relation: "member_of", Source: store.EdgeSourceGuest, CreatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.InsertBundleItem(&store.BundleItem{ID: r.item, SponsorshipID: r.sponsorship, GuestID: r.guest, GroupID: r.group,
			System: "okta", Status: store.BundleGranted, EdgeID: &r.edge, ExpiresAt: storetest.Now.Add(48 * time.Hour),
			CreatedAt: storetest.Now, UpdatedAt: storetest.Now, GrantedAt: &storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func gaFixture(t *testing.T) (*storetest.Fixture, gaRows, gaRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedGuestAccess(t, f.DB, f.A, storetest.Sentinel), seedGuestAccess(t, f.DB, f.B, "b")
}

func gaDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := spDump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		items, err := c.BundleItems(store.BundleItemFilter{})
		if err != nil {
			return err
		}
		as, err := c.IdentityAssurances()
		if err != nil {
			return err
		}
		ps, err := c.CatalogPopulations("")
		if err != nil {
			return err
		}
		es, err := c.EdgesBySource(store.EdgeSourceGuest)
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{items, as, ps, es})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIsolation_GuestAccessReads(t *testing.T) {
	f, a, b := gaFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.BundleItem(a.item); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BundleItem(A's) = %v", err)
		}
		if x, err := c.BundleItem(b.item); err != nil || x.Status != store.BundleGranted {
			t.Errorf("BundleItem(B's) = %+v, %v", x, err)
		}
		if xs, err := c.BundleItems(store.BundleItemFilter{Sponsorship: a.sponsorship}); err != nil || len(xs) != 0 {
			t.Errorf("BundleItems(A's sponsorship) = %v, %v", xs, err)
		}
		if xs, err := c.BundleItems(store.BundleItemFilter{}); err != nil || len(xs) != 1 || xs[0].ID != b.item {
			t.Errorf("BundleItems() = %v, %v", xs, err)
		}
		if xs, err := c.BundleItems(store.BundleItemFilter{Edge: a.edge, Group: a.group}); err != nil || len(xs) > 1 {
			t.Errorf("BundleItems(A's edge) = %v, %v", xs, err)
		}
		if got, err := c.IdentityAssurance(b.guest); err != nil || got.Source != "claim b" {
			t.Errorf("IdentityAssurance(B's) = %+v, %v", got, err)
		}
		if got, err := c.IdentityAssurances(); err != nil || len(got) != 1 || got[0].Source != "claim b" {
			t.Errorf("IdentityAssurances = %+v, %v", got, err)
		}
		if ps, err := c.CatalogPopulations(a.catalogItem); err != nil || len(ps) != 0 {
			t.Errorf("CatalogPopulations(A's item) = %v, %v", ps, err)
		}
		if ps, err := c.CatalogPopulations(""); err != nil || len(ps) != 1 || ps[0].ItemID != b.catalogItem {
			t.Errorf("CatalogPopulations() = %v, %v", ps, err)
		}
		if es, err := c.EdgesBySource(store.EdgeSourceGuest); err != nil || len(es) != 1 || es[0].ID != b.edge {
			t.Errorf("EdgesBySource = %v, %v", es, err)
		}
		return nil
	})
}

var gaMutations = map[string]func(c *store.TenantTx, a, b gaRows) error{
	"SaveBundleItem": func(c *store.TenantTx, a, _ gaRows) error {
		return c.SaveBundleItem(&store.BundleItem{ID: a.item, Status: store.BundleRemoved, ExpiresAt: storetest.Now,
			UpdatedAt: storetest.Now, RemovedAt: &storetest.Now})
	},
	"SetCatalogPopulations/A's item": func(c *store.TenantTx, a, _ gaRows) error {
		// B's own tenant stamp is bound: a clear of A's item changes nothing, an insert for it is refused
		if err := c.SetCatalogPopulations(a.catalogItem, []string{store.PopPartner}); err != nil {
			return err
		}
		return store.ErrNotFound
	},
	"PutIdentityAssurance/A's person": func(c *store.TenantTx, a, _ gaRows) error {
		return c.PutIdentityAssurance(&store.Assurance{IdentityID: a.guest, IAL: 2, AAL: 2, Source: "x", RecordedAt: storetest.Now})
	},
	"InsertBundleItem/A's sponsorship": func(c *store.TenantTx, a, b gaRows) error {
		return c.InsertBundleItem(&store.BundleItem{ID: uuid.NewString(), SponsorshipID: a.sponsorship, GuestID: b.guest, GroupID: b.group,
			System: "okta", Status: store.BundlePending, ExpiresAt: storetest.Now, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"InsertBundleItem/A's person": func(c *store.TenantTx, a, b gaRows) error {
		return c.InsertBundleItem(&store.BundleItem{ID: uuid.NewString(), SponsorshipID: b.sponsorship, GuestID: a.guest, GroupID: b.group,
			System: "okta", Status: store.BundlePending, ExpiresAt: storetest.Now, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"InsertBundleItem/A's group": func(c *store.TenantTx, a, b gaRows) error {
		return c.InsertBundleItem(&store.BundleItem{ID: uuid.NewString(), SponsorshipID: b.sponsorship, GuestID: b.guest, GroupID: a.group,
			System: "okta", Status: store.BundlePending, ExpiresAt: storetest.Now, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
}

func TestIsolation_GuestAccessMutationsScoped(t *testing.T) {
	for name, fn := range gaMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := gaFixture(t)
			before := gaDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := gaDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
	// an insert of a population for A's catalog item from B is refused by the guard trigger
	f, a, _ := gaFixture(t)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.SetCatalogPopulations(a.catalogItem, []string{store.PopPartner})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("a population for another tenant's item = %v, want ErrCrossTenant", err)
	}
}

// The schema's own rules: a removed item is final, states and levels are
// bounded, an assurance level never goes down, one sponsorship holds a group once.
func TestGuestAccess_SchemaRules(t *testing.T) {
	f, _, b := gaFixture(t)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		x := &store.BundleItem{ID: "bi-dup", SponsorshipID: b.sponsorship, GuestID: b.guest, GroupID: b.group, System: "okta",
			Status: store.BundlePending, ExpiresAt: now, CreatedAt: now, UpdatedAt: now}
		if err := c.InsertBundleItem(x); err == nil {
			t.Error("a group twice in one sponsorship's bundle was accepted")
		}
		return nil
	})
	for name, mod := range map[string]func(x *store.BundleItem){
		"unknown status":    func(x *store.BundleItem) { x.Status = "bogus" },
		"removed w/o time":  func(x *store.BundleItem) { x.Status = store.BundleRemoved },
		"time but not done": func(x *store.BundleItem) { x.RemovedAt = &now },
		"no system":         func(x *store.BundleItem) { x.System = "" },
	} {
		x := &store.BundleItem{ID: uuid.NewString(), SponsorshipID: b.sponsorship, GuestID: b.guest, GroupID: b.group + 1000, System: "okta",
			Status: store.BundlePending, ExpiresAt: now, CreatedAt: now, UpdatedAt: now}
		mod(x)
		if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return c.InsertBundleItem(x) }); err == nil {
			t.Errorf("%s: an item the schema forbids was accepted", name)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		it, err := c.BundleItem(b.item)
		if err != nil {
			t.Fatal(err)
		}
		it.Status, it.RemovedAt = store.BundleRemoved, &now
		if err := c.SaveBundleItem(it); err != nil {
			t.Fatal(err)
		}
		it.Status, it.RemovedAt = store.BundleGranted, nil
		if err := c.SaveBundleItem(it); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a removed item was reopened: %v", err)
		}
		// an assurance level only goes up
		if err := c.PutIdentityAssurance(&store.Assurance{IdentityID: b.guest, IAL: 0, AAL: 1, Source: "later", RecordedAt: now}); err != nil {
			t.Fatal(err)
		}
		if a, err := c.IdentityAssurance(b.guest); err != nil || a.IAL != 1 || a.Source != "claim b" {
			t.Errorf("a lower level changed the record: %+v, %v", a, err)
		}
		if err := c.PutIdentityAssurance(&store.Assurance{IdentityID: b.guest, IAL: 2, AAL: 2, Source: "idv", RecordedAt: now}); err != nil {
			t.Fatal(err)
		}
		if a, err := c.IdentityAssurance(b.guest); err != nil || a.IAL != 2 || a.AAL != 2 || a.Source != "idv" {
			t.Errorf("a higher level was not recorded: %+v, %v", a, err)
		}
		if err := c.PutIdentityAssurance(&store.Assurance{IdentityID: b.guest, IAL: 3, AAL: 1, Source: "x", RecordedAt: now}); err == nil {
			t.Error("IAL 3 was accepted")
		}
		if err := c.SetCatalogPopulations(b.catalogItem, []string{"nobody"}); err == nil {
			t.Error("an unknown population was accepted")
		}
		return nil
	})
}

func guestAccessCovered() map[string]bool {
	out := map[string]bool{}
	for k := range gaMutations {
		out[k] = true
	}
	for _, k := range []string{"BundleItem", "BundleItems", "IdentityAssurance", "IdentityAssurances", "CatalogPopulations",
		"EdgesBySource", "InsertBundleItem", "PutIdentityAssurance", "SetCatalogPopulations", "SaveBundleItem"} {
		out[k] = true // TestIsolation_GuestAccessReads, and the writes in the seeds and mutation cases
	}
	return out
}
