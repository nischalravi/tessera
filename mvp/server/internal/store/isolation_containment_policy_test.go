package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The shared Deny policy of AWS containment (schema/0208): the lease and the
// ledger of denied users are per tenant, so one tenant's worker never waits on,
// reads or releases another tenant's policy lease, even for the same policy id.

const polID = "p-0a1b2c3d4e"

func containmentPolicyCovered() map[string]bool {
	return map[string]bool{"AcquirePolicyLease": true, "ReleasePolicyLease": true, // TestIsolation_PolicyLeaseIsPerTenant
		"MarkPolicyDenial": true, "PolicyDenials": true, "PrunePolicyDenials": true, // TestIsolation_PolicyDenialsAreTenantScoped
		"PlatformUserIDsForIdentity": true} // TestIsolation_PlatformUsersForIdentity
}

func TestIsolation_PolicyLeaseIsPerTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	now := storetest.Now
	try := func(tn storetest.Tenant, holder string, at time.Time) bool {
		var ok bool
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) (err error) {
			ok, err = c.AcquirePolicyLease(polID, holder, at, at.Add(time.Minute))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !try(f.A, "a1", now) {
		t.Fatal("A could not take a free lease")
	}
	if try(f.A, "a2", now.Add(time.Second)) {
		t.Error("a second holder took A's unexpired lease")
	}
	if !try(f.B, "b1", now) {
		t.Error("B was blocked by A's lease on the same policy id")
	}
	// B releasing with A's holder token changes nothing for A, and a stranger cannot release
	if err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error { return c.ReleasePolicyLease(polID, "a1") }); err != nil {
		t.Fatal(err)
	}
	if try(f.A, "a2", now.Add(2*time.Second)) {
		t.Error("B's release freed A's lease")
	}
	// the holder extends its own lease; an expired lease is taken over
	if !try(f.A, "a1", now.Add(3*time.Second)) {
		t.Error("the holder could not extend its lease")
	}
	if !try(f.A, "a2", now.Add(5*time.Minute)) {
		t.Error("an expired lease was not taken over")
	}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.ReleasePolicyLease(polID, "a2") }); err != nil {
		t.Fatal(err)
	}
	if !try(f.A, "a3", now.Add(5*time.Minute)) {
		t.Error("a released lease was not free")
	}
}

func TestIsolation_PolicyDenialsAreTenantScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	now := storetest.Now
	for _, m := range []struct {
		tn   storetest.Tenant
		user string
	}{{f.A, "user-a"}, {f.B, "user-b"}} {
		if err := f.DB.InTenant(ctx, m.tn.ID, func(c *store.TenantTx) error {
			return c.MarkPolicyDenial(polID, m.user, store.DenialPending, now)
		}); err != nil {
			t.Fatal(err)
		}
	}
	list := func(tn storetest.Tenant, since time.Time) []string {
		var out []string
		if err := f.DB.ReadTenant(ctx, tn.ID, func(c *store.TenantTx) (err error) {
			out, err = c.PolicyDenials(polID, since)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := list(f.A, now.Add(-time.Hour)); !slices.Equal(got, []string{"user-a"}) {
		t.Errorf("A sees %v", got)
	}
	if got := list(f.B, now.Add(-time.Hour)); !slices.Equal(got, []string{"user-b"}) {
		t.Errorf("B sees %v", got)
	}
	// B's mark and prune leave A's rows alone; state moves pending -> active
	if err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		if err := c.MarkPolicyDenial(polID, "user-a", store.DenialActive, now); err != nil {
			return err
		}
		return c.PrunePolicyDenials(polID, now.Add(time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	if got := list(f.A, now.Add(-time.Hour)); !slices.Equal(got, []string{"user-a"}) {
		t.Errorf("after B's prune A sees %v", got)
	}
	if got := list(f.B, now.Add(-time.Hour)); len(got) != 0 {
		t.Errorf("B's pruned rows are still listed: %v", got)
	}
	// an old entry is not listed
	if got := list(f.A, now.Add(time.Minute)); len(got) != 0 {
		t.Errorf("an entry older than since is listed: %v", got)
	}
}

func TestIsolation_PlatformUsersForIdentity(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	aliceA, aliceB := f.A.IDs["alice"], f.B.IDs["alice"]
	for _, tn := range []struct {
		tn       storetest.Tenant
		identity int64
	}{{f.A, aliceA}, {f.B, aliceB}} {
		if err := f.DB.InTenant(ctx, tn.tn.ID, func(c *store.TenantTx) error {
			if err := c.InsertPlatformUser(&store.PlatformUser{TenantID: tn.tn.ID, DisplayName: "linked " + tn.tn.Slug,
				IdentityID: &tn.identity, CreatedAt: storetest.Now}); err != nil {
				return err
			}
			return c.InsertPlatformUser(&store.PlatformUser{TenantID: tn.tn.ID, DisplayName: "unlinked", CreatedAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		ids, err := c.PlatformUserIDsForIdentity(aliceB)
		if err != nil || len(ids) != 1 {
			t.Fatalf("B's alice: %v, %v", ids, err)
		}
		if u, err := c.PlatformUser(ids[0]); err != nil || u.DisplayName != "linked "+f.B.Slug {
			t.Errorf("user %+v, %v", u, err)
		}
		// A's identity id names nobody in B
		if ids, err := c.PlatformUserIDsForIdentity(aliceA); err != nil || (aliceA != aliceB && len(ids) != 0) {
			t.Errorf("A's identity in B: %v, %v", ids, err)
		}
		return nil
	})
}
