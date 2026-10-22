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

// srcFeed is the identities connection src reports: n people prefix-00.., the first `ended` of them terminated.
func srcFeed(src, prefix string, n, ended int) *connectors.DiscoveryResult {
	r := &connectors.DiscoveryResult{SourceID: src}
	for i := 0; i < n; i++ {
		x := fmt.Sprintf("%s-%02d", prefix, i)
		st := "active"
		if i < ended {
			st = "terminated"
		}
		r.Identities = append(r.Identities, connectors.IdentityRecord{ExternalID: x, Name: "Person " + x, Type: "human", Status: st})
	}
	return r
}

// The previous record count of an identity feed is the source's own last good run, not the tenant's
// active identities; a source's own feed settings apply to it alone.
func TestIdentityFeedIsMeasuredAgainstItsOwnSource(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	var tick int
	sync := func(rs ...*connectors.DiscoveryResult) {
		t.Helper()
		tick++
		at := now.Add(time.Duration(tick) * time.Minute)
		if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
			_, err := ingest.Discovery(c, at, rs, false)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(fn func(c *store.TenantTx)) {
		t.Helper()
		if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error { fn(c); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	status := func(c *store.TenantTx, x string) string {
		i, err := c.IdentityByExternalID(x)
		if err != nil {
			t.Fatal(err)
		}
		return i.Status
	}
	holds := func(c *store.TenantTx) []*store.DeletionHold {
		hs, err := c.DeletionHolds("held", "identities", 20, 0)
		if err != nil {
			t.Fatal(err)
		}
		return hs
	}

	sync(srcFeed("connA", "a", 50, 0))
	sync(srcFeed("connB", "b", 10, 0))
	read(func(c *store.TenantTx) {
		for src, want := range map[string]int{"connA": 50, "connB": 10} {
			if n, ok, err := c.DeletionSourceCount("connection", src, "identities"); err != nil || !ok || n != want {
				t.Errorf("%s last count = %d %v %v, want %d", src, n, ok, err, want)
			}
		}
	})

	// B reports 9 records, one ended: a 10% drop against B's own 10. (Against the tenant's 60 active
	// identities it would be 85% and the removal would be held.)
	sync(srcFeed("connB", "b", 9, 1))
	read(func(c *store.TenantTx) {
		if got := status(c, "b-00"); got == "active" {
			t.Errorf("b-00 is %s: B's removal was held on the tenant-wide count", got)
		}
		if hs := holds(c); len(hs) != 0 {
			t.Errorf("holds = %v", hs)
		}
		if n, _, _ := c.DeletionSourceCount("connection", "connB", "identities"); n != 9 {
			t.Errorf("B's last count = %d, want 9", n)
		}
	})

	// A reports 30 of its 50, one ended: a 40% drop against A's own count is held, with its reasons
	sync(srcFeed("connA", "a", 30, 1))
	read(func(c *store.TenantTx) {
		if got := status(c, "a-00"); got != "active" {
			t.Errorf("a-00 is %s: the truncated feed's removal was applied", got)
		}
		hs := holds(c)
		if len(hs) != 1 || hs[0].SourceID != "connA" || !strings.Contains(hs[0].Reason, `"previous_count":50`) ||
			!strings.Contains(hs[0].Reason, "40% fewer") || !strings.Contains(hs[0].Reason, `"source_kind":"connection"`) {
			t.Fatalf("holds = %+v", hs)
		}
		if n, _, _ := c.DeletionSourceCount("connection", "connA", "identities"); n != 50 {
			t.Errorf("a flagged feed moved A's last good count to %d", n)
		}
	})

	// A's own limit is 50%: the same truncation passes, B (default 20) is unaffected by it
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		d := 50.0
		return deleteguard.SetSource(c, deleteguard.SourcePolicy{Kind: "connection", SourceID: "connA", Category: deleteguard.CatIdentities, FeedDropPercent: &d}, nil, now)
	}); err != nil {
		t.Fatal(err)
	}
	r := srcFeed("connA", "a", 30, 0)
	r.Identities[1].Status = "terminated" // a-01
	sync(r)
	read(func(c *store.TenantTx) {
		if got := status(c, "a-01"); got == "active" {
			t.Errorf("a-01 is %s: A's 50%% limit did not apply", got)
		}
		if n, _, _ := c.DeletionSourceCount("connection", "connA", "identities"); n != 30 {
			t.Errorf("A's last count = %d, want 30", n)
		}
	})
	// the same 40% drop on B (limit 20) is held: A's setting is A's alone
	sync(srcFeed("connB", "b", 5, 1)) // b-00 is already ended; b-00 reports ended again, so use b-01
	r = srcFeed("connB", "b", 5, 0)
	r.Identities[1].Status = "terminated" // b-01
	sync(r)
	read(func(c *store.TenantTx) {
		if got := status(c, "b-01"); got != "active" {
			t.Errorf("b-01 is %s: B's feed dropped from 9 to 5 and was not held", got)
		}
	})
}

// A result with no source is judged under the tenant's settings and the tenant-wide count, as before.
func TestUnattributedResultKeepsTheTenantBasis(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	in := func(at time.Time, r *connectors.DiscoveryResult) {
		t.Helper()
		if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
			_, err := ingest.Discovery(c, at, []*connectors.DiscoveryResult{r}, false)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	in(now, srcFeed("", "u", 40, 0))
	in(now.Add(time.Minute), srcFeed("", "u", 10, 1)) // 40 -> 10 records, one ended
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		hs, err := c.DeletionHolds("held", "identities", 5, 0)
		if err != nil || len(hs) != 1 || hs[0].SourceID != "" {
			t.Errorf("holds = %+v %v", hs, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
