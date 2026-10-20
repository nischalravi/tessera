package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Two-person activation requests (DR-10, schema/0208): a tenant sees and
// decides only its own requests, another tenant's connection or revision id
// looks nonexistent, and a row naming one is refused by the guard trigger.
// Tenant B's rows carry storetest.ReadinessSentinel.

func activationReq(t storetest.Tenant, who string) *store.ActivationRequest {
	return &store.ActivationRequest{ID: store.NewID(), ConnectionID: t.Refs["connection:ad"], RevisionID: t.Refs["revision:ad"],
		ConfigHash: "h", WriteMode: "scoped", RequestedByKey: "user:" + who, RequestedBy: who,
		RequestedAt: storetest.Now, ExpiresAt: storetest.Now.Add(72 * time.Hour)}
}

func seedActivation(t *testing.T, f *storetest.Fixture) (a, b *store.ActivationRequest) {
	t.Helper()
	a, b = activationReq(f.A, "alice"), activationReq(f.B, "bob "+storetest.ReadinessSentinel)
	for _, s := range []struct {
		tn storetest.Tenant
		r  *store.ActivationRequest
	}{{f.A, a}, {f.B, b}} {
		if err := f.DB.InTenant(context.Background(), s.tn.ID, func(c *store.TenantTx) error {
			return c.InsertActivationRequest(s.r)
		}); err != nil {
			t.Fatal(err)
		}
	}
	return a, b
}

func TestIsolation_ReadinessTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedActivation(t, f)
	ctx := context.Background()

	t.Run("reads return only own rows", func(t *testing.T) {
		if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
			got, err := c.PendingActivationRequest(f.A.Refs["connection:ad"])
			if err != nil || got.ID != a.ID || strings.Contains(got.RequestedBy, storetest.ReadinessSentinel) {
				t.Errorf("A's own request = %+v, %v", got, err)
			}
			if _, err := c.PendingActivationRequest(f.B.Refs["connection:ad"]); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Pending(B's connection) in A = %v, want ErrNotFound", err)
			}
			if _, err := c.LatestActivationRequest(f.B.Refs["connection:ad"]); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Latest(B's connection) in A = %v, want ErrNotFound", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// positive control: B's own row carries the sentinel
		if err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
			got, err := c.PendingActivationRequest(f.B.Refs["connection:ad"])
			if err != nil || got.ID != b.ID || !strings.Contains(got.RequestedBy, storetest.ReadinessSentinel) {
				t.Errorf("B's own request = %+v, %v", got, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a decision of another tenant's request changes nothing", func(t *testing.T) {
		err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
			return c.DecideActivationRequest(b.ID, store.ActivationRejected, "user:alice", "alice", "x", storetest.Now)
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("A deciding B's request = %v, want ErrNotFound", err)
		}
		if err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
			got, err := c.PendingActivationRequest(f.B.Refs["connection:ad"])
			if err != nil || got.Status != store.ActivationPending {
				t.Errorf("B's request after A's attempt = %+v, %v", got, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a row naming another tenant's connection or revision is refused", func(t *testing.T) {
		// close A's open request so the unique open index is not what refuses
		if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
			return c.DecideActivationRequest(a.ID, store.ActivationCancelled, "user:alice", "alice", "", storetest.Now)
		}); err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*store.ActivationRequest){
			"connection_id": func(r *store.ActivationRequest) { r.ConnectionID = f.B.Refs["connection:ad"] },
			"revision_id":   func(r *store.ActivationRequest) { r.RevisionID = f.B.Refs["revision:ad"] },
		} {
			r := activationReq(f.A, "carol")
			mutate(r)
			err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.InsertActivationRequest(r) })
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("%s: err = %v, want ErrCrossTenant", name, err)
			}
		}
	})
}

// TestActivationRequests_Constraints: one open request per revision, and an
// applied request cannot be decided by its requester (the schema enforces
// the two-person rule as well as the service).
func TestActivationRequests_Constraints(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, _ := seedActivation(t, f)
	ctx := context.Background()
	dup := activationReq(f.A, "dave")
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.InsertActivationRequest(dup) }); err == nil {
		t.Error("a second open request for the same revision was accepted")
	}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.DecideActivationRequest(a.ID, store.ActivationApplied, a.RequestedByKey, a.RequestedBy, "", storetest.Now)
	}); err == nil {
		t.Error("the requester applied their own request")
	}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.DecideActivationRequest(a.ID, store.ActivationApplied, "user:erin", "erin", "", storetest.Now)
	}); err != nil {
		t.Errorf("a different person applying: %v", err)
	}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.DecideActivationRequest(a.ID, store.ActivationRejected, "user:erin", "erin", "", storetest.Now)
	}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("deciding an applied request again = %v, want ErrNotFound", err)
	}
}

func activationCovered() map[string]bool {
	// TestIsolation_ReadinessTables and TestActivationRequests_Constraints
	return map[string]bool{"InsertActivationRequest": true, "PendingActivationRequest": true,
		"LatestActivationRequest": true, "DecideActivationRequest": true}
}
