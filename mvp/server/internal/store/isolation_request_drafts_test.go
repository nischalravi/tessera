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

// Request drafts (schema/0312): private to their user and to their tenant.
// Another tenant's, or another user's, id looks nonexistent and a row naming
// another tenant's user is refused by the guard trigger.

type draftRows struct {
	user  *store.PlatformUser
	other *store.PlatformUser // a second user of the same tenant
	id    string
}

func seedDrafts(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) draftRows {
	t.Helper()
	r := draftRows{id: "draft-" + tag}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.user = &store.PlatformUser{DisplayName: "drafter " + tag, CreatedAt: storetest.Now}
		r.other = &store.PlatformUser{DisplayName: "colleague " + tag, CreatedAt: storetest.Now}
		for _, u := range []*store.PlatformUser{r.user, r.other} {
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
		}
		h := 8.0
		return c.InsertRequestDraft(&store.RequestDraft{ID: r.id, UserID: r.user.ID.String(), BeneficiaryIDs: []int64{tn.IDs["alice"]},
			Items: json.RawMessage(`[{"kind":"group","group_id":1}]`), DurationHours: &h, Justification: "j " + tag}, storetest.Now)
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func draftFixture(t *testing.T) (*storetest.Fixture, draftRows, draftRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedDrafts(t, f.DB, f.A, "a"), seedDrafts(t, f.DB, f.B, "b")
}

func TestIsolation_RequestDraftReads(t *testing.T) {
	f, a, b := draftFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		ds, err := c.RequestDrafts(b.user.ID.String())
		if err != nil || len(ds) != 1 || ds[0].ID != b.id || ds[0].DurationHours == nil || *ds[0].DurationHours != 8 || len(ds[0].BeneficiaryIDs) != 1 {
			t.Errorf("RequestDrafts = %v, %v", ds, err)
		}
		// A's user, A's draft id: nothing in B
		if ds, err := c.RequestDrafts(a.user.ID.String()); err != nil || len(ds) != 0 {
			t.Errorf("RequestDrafts(A's user) = %v, %v", ds, err)
		}
		if _, err := c.RequestDraft(a.id, a.user.ID.String()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RequestDraft(A's) = %v", err)
		}
		// B's own draft, asked for as a colleague, is private too
		if _, err := c.RequestDraft(b.id, b.other.ID.String()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RequestDraft(colleague) = %v", err)
		}
		if n, err := c.CountRequestDrafts(a.user.ID.String()); err != nil || n != 0 {
			t.Errorf("CountRequestDrafts(A's user) = %d, %v", n, err)
		}
		return nil
	})
}

var draftMutations = map[string]func(c *store.TenantTx, a, b draftRows) error{
	"UpdateRequestDraft": func(c *store.TenantTx, a, _ draftRows) error {
		return c.UpdateRequestDraft(&store.RequestDraft{ID: a.id, UserID: a.user.ID.String(), Justification: "taken"}, storetest.Now)
	},
	"DeleteRequestDraft": func(c *store.TenantTx, a, _ draftRows) error {
		return c.DeleteRequestDraft(a.id, a.user.ID.String())
	},
	"InsertRequestDraft": func(c *store.TenantTx, a, _ draftRows) error {
		return c.InsertRequestDraft(&store.RequestDraft{ID: "x", UserID: a.user.ID.String(), Justification: "x"}, storetest.Now)
	},
}

func TestIsolation_RequestDraftMutationsScoped(t *testing.T) {
	for name, fn := range draftMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := draftFixture(t)
			before := draftDump(t, f.DB, f.A, a)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := draftDump(t, f.DB, f.A, a); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func TestRequestDrafts_OwnerOnlyWrites(t *testing.T) {
	f, _, b := draftFixture(t)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		// a colleague in the same tenant can neither change nor delete it
		if err := c.UpdateRequestDraft(&store.RequestDraft{ID: b.id, UserID: b.other.ID.String(), Justification: "taken"}, storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("colleague update = %v", err)
		}
		if err := c.DeleteRequestDraft(b.id, b.other.ID.String()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("colleague delete = %v", err)
		}
		d, err := c.RequestDraft(b.id, b.user.ID.String())
		if err != nil || d.Justification != "j b" {
			t.Errorf("the owner's draft = %+v, %v", d, err)
		}
		d.Justification = "edited"
		if err := c.UpdateRequestDraft(d, storetest.Now.Add(time.Hour)); err != nil {
			return err
		}
		if d, err = c.RequestDraft(b.id, b.user.ID.String()); err != nil || d.Justification != "edited" || !d.UpdatedAt.After(d.CreatedAt) {
			t.Errorf("after update = %+v, %v", d, err)
		}
		return c.DeleteRequestDraft(b.id, b.user.ID.String())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func draftDump(t *testing.T, db *store.DB, tn storetest.Tenant, r draftRows) string {
	t.Helper()
	out := storetest.Dump(t, db, tn.ID)
	err := db.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		ds, err := c.RequestDrafts(r.user.ID.String())
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

func requestDraftsCovered() map[string]bool {
	return map[string]bool{"InsertRequestDraft": true, "UpdateRequestDraft": true, "DeleteRequestDraft": true, // TestIsolation_RequestDraftMutationsScoped
		"RequestDraft": true, "RequestDrafts": true, "CountRequestDrafts": true} // TestIsolation_RequestDraftReads
}
