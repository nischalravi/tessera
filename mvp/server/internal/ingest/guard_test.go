package ingest_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// feed is a source of n people, each with an account in "hr", all with the given status.
func feed(n int, status string) *connectors.DiscoveryResult {
	r := &connectors.DiscoveryResult{}
	for i := 0; i < n; i++ {
		x := fmt.Sprintf("guard-%02d", i)
		r.Identities = append(r.Identities, connectors.IdentityRecord{ExternalID: x, Name: "Person " + x, Type: "human", Status: status})
		r.Accounts = append(r.Accounts, connectors.AccountRecord{System: "hr", ExternalID: x, Username: x, Kind: "user", Status: map[string]string{"active": "active", "terminated": "disabled"}[status],
			Identity: &connectors.IdentityRef{ExternalID: x}})
	}
	return r
}

func statuses(t *testing.T, f *storetest.Fixture, n int) (ended, accountsOff int) {
	t.Helper()
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		for i := 0; i < n; i++ {
			x := fmt.Sprintf("guard-%02d", i)
			if id, err := c.IdentityByExternalID(x); err != nil {
				return err
			} else if id.Status != "active" {
				ended++
			}
			if a, err := c.AccountByXID("hr", x); err != nil {
				return err
			} else if a.Status != "active" {
				accountsOff++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ended, accountsOff
}

// A source that suddenly reports everyone as terminated is held past the default thresholds
// (identities: the lower of 50 and 2% of the tenant, never fewer than 5; accounts the same shape),
// the rest stays active, and a second admin's release applies it.
func TestSyncHoldsMassTerminationsAndDisables(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	in := func(fn func(c *store.TenantTx) error) {
		t.Helper()
		if err := f.DB.InTenant(context.Background(), f.A.ID, fn); err != nil {
			t.Fatal(err)
		}
	}
	const n = 30
	in(func(c *store.TenantTx) error {
		_, err := ingest.Discovery(c, now, []*connectors.DiscoveryResult{feed(n, "active")}, false)
		return err
	})
	if e, a := statuses(t, f, n); e != 0 || a != 0 {
		t.Fatalf("a first sync ended %d identities and %d accounts", e, a)
	}
	var stats ingest.DiscoveryStats
	in(func(c *store.TenantTx) (err error) {
		stats, err = ingest.Discovery(c, now.Add(time.Hour), []*connectors.DiscoveryResult{feed(n, "terminated")}, false)
		return err
	})
	ended, off := statuses(t, f, n)
	if ended != 5 || off != 5 || stats.HeldIdentities != n-5 || stats.HeldAccounts != n-5 {
		t.Fatalf("ended %d, accounts disabled %d, held %d identities and %d accounts", ended, off, stats.HeldIdentities, stats.HeldAccounts)
	}
	// the deterministic order: the first five by ref were let through
	in(func(c *store.TenantTx) error {
		hs, err := c.DeletionHolds("held", "", 10, 0)
		if err != nil || len(hs) != 2 {
			t.Fatalf("holds = %v, %v", hs, err)
		}
		for _, h := range hs {
			if h.Source != "connector" || h.ItemCount != n-5 {
				t.Errorf("hold %+v", h)
			}
		}
		return nil
	})

	// a second sync in the same window holds all of them again
	in(func(c *store.TenantTx) error {
		_, err := ingest.Discovery(c, now.Add(2*time.Hour), []*connectors.DiscoveryResult{feed(n, "terminated")}, false)
		return err
	})
	in(func(c *store.TenantTx) error {
		hs, _ := c.DeletionHolds("held", deleteguard.CatIdentities, 10, 0)
		if len(hs) != 2 { // each sync is its own correlation: its own hold
			t.Errorf("identity holds after a second sync = %d", len(hs))
		}
		return nil
	})

	// release every hold: the identities end and their accounts are disabled
	appliers := deleteguard.Appliers{ingest.ItemIdentityStatus: ingest.ReleaseIdentity, ingest.ItemAccountStatus: ingest.ReleaseAccount}
	in(func(c *store.TenantTx) error {
		hs, _ := c.DeletionHolds("held", "", 10, 0)
		for _, h := range hs {
			if _, err := deleteguard.Release(c, now.Add(3*time.Hour), h.ID, "approver", nil, appliers); err != nil {
				return err
			}
		}
		return nil
	})
	if e, a := statuses(t, f, n); e != n || a != n {
		t.Errorf("after the releases %d identities ended and %d accounts disabled, want all %d", e, a, n)
	}
}
