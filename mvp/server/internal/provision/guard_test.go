package provision_test

import (
	"fmt"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Disable and delete operations count against the accounts threshold: past it the operation is
// not queued but held with everything needed to queue it again; a different admin's release
// queues it (an approved override that is not counted again). Other kinds are not guarded.
func TestDisableOperationsOverTheThresholdAreHeldAndReleased(t *testing.T) {
	e := setup(t, fake.Options{})
	limit := 2
	e.inA(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatAccounts, MaxCount: &limit, WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess}, nil, e.now)
	})
	submit := func(c *store.TenantTx, kind string, i int) *store.ProvOp {
		t.Helper()
		op, routed, err := provision.Submit(c, e.now, provision.Change{System: e.system, Kind: kind,
			Account: target.Account{Username: fmt.Sprintf("leaver%d", i)}, Source: provision.SourceJML, Key: fmt.Sprintf("guard:%s:%d", kind, i)})
		if err != nil || !routed {
			t.Fatalf("submit %s %d: routed %v, %v", kind, i, routed, err)
		}
		return op
	}
	e.inA(func(c *store.TenantTx) error {
		var held, queued int
		for i := 0; i < 4; i++ {
			op := submit(c, target.DisableAccount, i)
			if op.Status == provision.Held {
				held++
			} else {
				queued++
			}
		}
		if queued != 2 || held != 2 {
			t.Errorf("queued %d held %d, want 2 and 2", queued, held)
		}
		// an entitlement removal or an add is not an account removal: never held
		for i := 0; i < 3; i++ {
			op, _, err := provision.Submit(c, e.now, provision.Change{System: e.system, Kind: target.AddEntitlement,
				Account: target.Account{Username: "someone"}, Group: target.Group{Name: "g"}, Source: provision.SourceAPI, Key: fmt.Sprintf("guard:add:%d", i)})
			if err != nil || op.Status != provision.Queued {
				t.Errorf("add entitlement = %+v, %v", op, err)
			}
		}
		ops, err := c.ProvOps(store.ProvOpFilter{})
		if err != nil {
			return err
		}
		if len(ops) != 5 {
			t.Errorf("%d operations stored, want the 2 disables and 3 adds", len(ops))
		}
		hs, err := c.DeletionHolds("held", deleteguard.CatAccounts, 10, 0)
		if err != nil || len(hs) != 1 || hs[0].ItemCount != 2 || hs[0].Source != "provisioner" || hs[0].SourceID != e.conn {
			t.Fatalf("holds %+v %v", hs, err)
		}
		// the same intent submitted again while it is held joins the hold without duplicating its item
		submit(c, target.DisableAccount, 3)
		if h, _ := c.DeletionHoldByID(hs[0].ID); h.ItemCount != 2 {
			t.Errorf("a retried held operation made %d items", h.ItemCount)
		}
		// release: the operations are queued, and the window is not charged again
		before, _ := c.DeletionsApplied(deleteguard.CatAccounts, e.now.Add(-1))
		res, err := deleteguard.Release(c, e.now, hs[0].ID, "approver", nil, deleteguard.Appliers{provision.ItemOp: provision.ReleaseHeld})
		if err != nil || res.Released != 2 {
			t.Fatalf("release = %+v, %v", res, err)
		}
		if after, _ := c.DeletionsApplied(deleteguard.CatAccounts, e.now.Add(-1)); after != before {
			t.Errorf("the window grew from %d to %d on a release", before, after)
		}
		ops, _ = c.ProvOps(store.ProvOpFilter{})
		if len(ops) != 7 {
			t.Errorf("%d operations after the release, want 7", len(ops))
		}
		return nil
	})
}
