package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Removal requests (schema/0311): a tenant sees and changes only its own;
// another tenant's ids look nonexistent and rows naming them are refused by
// the guard triggers.

type removalRows struct {
	user  *store.PlatformUser
	req   string
	alice int64
	acct  int64
	group int64
}

func seedRemovals(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) removalRows {
	t.Helper()
	r := removalRows{req: "rm-" + tag, alice: tn.IDs["alice"], acct: tn.IDs["acct:okta:alice"], group: tn.IDs["group:okta:eng"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.user = &store.PlatformUser{DisplayName: "requester " + tag, CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		return c.InsertRemovalRequest(&store.RemovalRequest{ID: r.req, BeneficiaryID: r.alice, AccountID: r.acct, GroupID: r.group,
			RequestedBy: r.user.ID.String(), Justification: "j " + tag, RequestedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func removalFixture(t *testing.T) (*storetest.Fixture, removalRows, removalRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedRemovals(t, f.DB, f.A, "a"), seedRemovals(t, f.DB, f.B, "b")
}

func TestIsolation_RemovalReads(t *testing.T) {
	f, a, b := removalFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		qs, err := c.RemovalRequests(store.RemovalRequestFilter{})
		if err != nil || len(qs) != 1 || qs[0].ID != b.req {
			t.Errorf("RemovalRequests = %v, %v", qs, err)
		}
		if qs, err := c.RemovalRequests(store.RemovalRequestFilter{InvolvingUser: a.user.ID.String(), InvolvingIdentity: a.alice}); err != nil || len(qs) != 0 {
			t.Errorf("RemovalRequests(A's user) = %v, %v", qs, err)
		}
		if _, err := c.RemovalRequest(a.req); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RemovalRequest(A's) = %v", err)
		}
		return nil
	})
}

var removalMutations = map[string]func(c *store.TenantTx, a, b removalRows) error{
	"SaveRemovalRequest": func(c *store.TenantTx, a, _ removalRows) error {
		return c.SaveRemovalRequest(&store.RemovalRequest{ID: a.req, Status: store.RequestCancelled}, store.RequestPending)
	},
	"InsertRemovalRequest": func(c *store.TenantTx, a, b removalRows) error {
		// B's request naming A's identity, account and group
		return c.InsertRemovalRequest(&store.RemovalRequest{ID: "x", BeneficiaryID: a.alice, AccountID: a.acct, GroupID: a.group,
			RequestedBy: b.user.ID.String(), Justification: "x", RequestedAt: storetest.Now})
	},
}

func TestIsolation_RemovalMutationsScoped(t *testing.T) {
	for name, fn := range removalMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := removalFixture(t)
			before := removalDump(t, f.DB, f.A)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := removalDump(t, f.DB, f.A); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func TestRemoval_OnePendingPerGrant(t *testing.T) {
	f, a, _ := removalFixture(t)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		dup := &store.RemovalRequest{ID: "dup", BeneficiaryID: a.alice, AccountID: a.acct, GroupID: a.group,
			RequestedBy: a.user.ID.String(), Justification: "x", RequestedAt: storetest.Now}
		if err := c.InsertRemovalRequest(dup); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("second pending removal = %v, want ErrDuplicate", err)
		}
		q, err := c.RemovalRequest(a.req)
		if err != nil {
			return err
		}
		q.Status = store.RequestDenied
		if err := c.SaveRemovalRequest(q, store.RequestPending); err != nil {
			return err
		}
		if err := c.SaveRemovalRequest(q, store.RequestPending); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("deciding twice = %v, want ErrNotFound", err)
		}
		return c.InsertRemovalRequest(dup) // a decided one does not collide
	})
	if err != nil {
		t.Fatal(err)
	}
}

func removalDump(t *testing.T, db *store.DB, tn storetest.Tenant) string {
	t.Helper()
	out := storetest.Dump(t, db, tn.ID)
	err := db.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		qs, err := c.RemovalRequests(store.RemovalRequestFilter{})
		if err != nil {
			return err
		}
		b, err := json.Marshal(qs)
		out += "\n" + string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func removalsCovered() map[string]bool {
	return map[string]bool{"InsertRemovalRequest": true, "SaveRemovalRequest": true, // TestIsolation_RemovalMutationsScoped
		"RemovalRequest": true, "RemovalRequests": true} // TestIsolation_RemovalReads
}
