package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Pending OAuth revoke requests (issue #107, schema/0470): a tenant sees,
// finds and executes only its own requests, and a request naming another
// tenant's user is refused by the guard triggers.

func seedRevokeRequests(t *testing.T, f *storetest.Fixture) (users map[string]uuid.UUID, reqs map[string]string) {
	t.Helper()
	users, reqs = map[string]uuid.UUID{}, map[string]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			u := &store.PlatformUser{DisplayName: "admin " + tn.Slug, CreatedAt: storetest.Now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			r := &store.OAuthRevokeRequest{Scope: store.OAuthRevokeVendor, Target: "acme", Reason: "vendor breached", Apps: 2, Grants: 5,
				RequestedByUserID: u.ID, RequestedBy: u.DisplayName, RequestedAt: storetest.Now, ExpiresAt: storetest.Now.Add(time.Hour)}
			if err := c.InsertOAuthRevokeRequest(r); err != nil {
				return err
			}
			users[tn.Slug], reqs[tn.Slug] = u.ID, r.ID
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return users, reqs
}

func TestIsolation_OAuthRevokeRequests(t *testing.T) {
	f := storetest.TwoTenants(t)
	users, reqs := seedRevokeRequests(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		got, err := c.PendingOAuthRevokeRequest(store.OAuthRevokeVendor, "acme", storetest.Now)
		if err != nil || got.ID != reqs[f.B.Slug] || got.Apps != 2 || got.Grants != 5 {
			t.Errorf("PendingOAuthRevokeRequest = %+v, %v", got, err)
		}
		list, err := c.PendingOAuthRevokeRequests(storetest.Now)
		if err != nil || len(list) != 1 || list[0].ID != reqs[f.B.Slug] {
			t.Errorf("PendingOAuthRevokeRequests = %v, %v", list, err)
		}
		// A's request cannot be executed from B
		if err := c.ExecuteOAuthRevokeRequest(reqs[f.A.Slug], users[f.B.Slug], "b", storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Execute(A's request) in B = %v, want ErrNotFound", err)
		}
		// expiring B's requests leaves A's alone
		return c.ExpireOAuthRevokeRequests(storetest.Now.Add(2 * time.Hour))
	})
	inA(t, f, func(c *store.TenantTx) error {
		got, err := c.PendingOAuthRevokeRequest(store.OAuthRevokeVendor, "acme", storetest.Now)
		if err != nil || got.ID != reqs[f.A.Slug] || got.Status != store.OAuthRevokePending {
			t.Errorf("A's request after B's expiry = %+v, %v", got, err)
		}
		return nil
	})
}

func TestOAuthRevokeRequestLifecycle(t *testing.T) {
	f := storetest.TwoTenants(t)
	users, reqs := seedRevokeRequests(t, f)
	inA(t, f, func(c *store.TenantTx) error {
		// an expired request is not pending, and is marked expired
		if _, err := c.PendingOAuthRevokeRequest(store.OAuthRevokeVendor, "acme", storetest.Now.Add(2*time.Hour)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("expired request found: %v", err)
		}
		if err := c.ExecuteOAuthRevokeRequest(reqs[f.A.Slug], users[f.A.Slug], "second", storetest.Now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		// executing twice finds nothing pending
		if err := c.ExecuteOAuthRevokeRequest(reqs[f.A.Slug], users[f.A.Slug], "second", storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second execute = %v, want ErrNotFound", err)
		}
		if _, err := c.PendingOAuthRevokeRequest(store.OAuthRevokeVendor, "acme", storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("executed request still pending: %v", err)
		}
		return nil
	})
}

func TestIsolation_OAuthRevokeRequestCrossTenantUser(t *testing.T) {
	f := storetest.TwoTenants(t)
	users, _ := seedRevokeRequests(t, f)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertOAuthRevokeRequest(&store.OAuthRevokeRequest{Scope: store.OAuthRevokeApp, Target: "x", Reason: "r",
			RequestedByUserID: users[f.A.Slug], RequestedBy: "a", RequestedAt: storetest.Now, ExpiresAt: storetest.Now.Add(time.Hour)})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Fatalf("err = %v, want ErrCrossTenant", err)
	}
}
