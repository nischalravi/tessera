package ingest_test

import (
	"context"
	"fmt"
	"strings"
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

// A source that suddenly reports everyone as terminated trips the default thresholds (identities:
// the lower of 50 and 2% of the tenant, never fewer than 5; accounts the same shape). A source-driven
// run holds the WHOLE removal set by default (hold_all), applying none of it; a second admin's
// release applies exactly the held set.
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
	if ended != 0 || off != 0 || stats.HeldIdentities != n || stats.HeldAccounts != n {
		t.Fatalf("ended %d, accounts disabled %d, held %d identities and %d accounts", ended, off, stats.HeldIdentities, stats.HeldAccounts)
	}
	// nothing was applied: the whole removal set is held as one batch per category
	in(func(c *store.TenantTx) error {
		hs, err := c.DeletionHolds("held", "", 10, 0)
		if err != nil || len(hs) != 2 {
			t.Fatalf("holds = %v, %v", hs, err)
		}
		for _, h := range hs {
			if h.Source != "connector" || h.ItemCount != n {
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
		hs, _ := c.DeletionHolds("held", "", 10, 0)
		if len(hs) != 2 { // the same corrupted feed again joins the open holds: no duplicate hold, no duplicate items
			t.Errorf("holds after a second identical sync = %d, want still 2", len(hs))
		}
		for _, h := range hs {
			if h.ItemCount != n {
				t.Errorf("hold %s has %d items", h.Category, h.ItemCount)
			}
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

// A truncated feed (30 people, the source now sends 20 and two of them ended) is held even though
// two is under the threshold: the feed itself looks broken. The reasons are on the hold.
func TestSyncHoldsEverythingFromATruncatedFeed(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	in := func(fn func(c *store.TenantTx) error) {
		t.Helper()
		if err := f.DB.InTenant(context.Background(), f.A.ID, fn); err != nil {
			t.Fatal(err)
		}
	}
	in(func(c *store.TenantTx) error {
		_, err := ingest.Discovery(c, now, []*connectors.DiscoveryResult{feed(30, "active")}, false)
		return err
	})
	small := feed(20, "active")
	small.Identities[0].Status, small.Identities[1].Status = "terminated", "terminated"
	in(func(c *store.TenantTx) error {
		_, err := ingest.Discovery(c, now.Add(time.Hour), []*connectors.DiscoveryResult{small}, false)
		return err
	})
	if e, _ := statuses(t, f, 30); e != 0 {
		t.Fatalf("%d identities ended by a truncated feed", e)
	}
	in(func(c *store.TenantTx) error {
		hs, err := c.DeletionHolds("held", deleteguard.CatIdentities, 10, 0)
		if err != nil || len(hs) != 1 || hs[0].ItemCount != 2 {
			t.Fatalf("holds %+v %v", hs, err)
		}
		if !strings.Contains(hs[0].Reason, "fewer than the last good run") || !strings.Contains(hs[0].Reason, `"previous_count":35`) || !strings.Contains(hs[0].Reason, `"new_count":20`) {
			t.Errorf("reason %s", hs[0].Reason)
		}
		return nil
	})
	// a partial read reported by the connector holds too, and a normal small change applies
	partial := feed(30, "active")
	partial.Identities[5].Status = "terminated"
	partial.Partial = "page 3 of 7 failed"
	in(func(c *store.TenantTx) error {
		_, err := ingest.Discovery(c, now.Add(2*time.Hour), []*connectors.DiscoveryResult{partial}, false)
		return err
	})
	if e, _ := statuses(t, f, 30); e != 0 {
		t.Fatalf("%d identities ended by a partial read", e)
	}
	ok := feed(30, "active")
	ok.Identities[7].Status = "terminated"
	in(func(c *store.TenantTx) error {
		_, err := ingest.Discovery(c, now.Add(3*time.Hour), []*connectors.DiscoveryResult{ok}, false)
		return err
	})
	// a hold is open for this source, but this removal is a normal small change of a complete feed:
	// hold_all applies only while over the threshold
	if e, _ := statuses(t, f, 30); e != 1 {
		t.Errorf("a normal small change ended %d identities, want 1", e)
	}
}
