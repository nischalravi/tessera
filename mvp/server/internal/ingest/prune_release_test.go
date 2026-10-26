package ingest_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// TestHeldEdgePruneIsReleasedByApplier: the edges a sync held stay until the hold is released; the
// applier then removes them (and not an edge that is gone already).
func TestHeldEdgePruneIsReleasedByApplier(t *testing.T) {
	db := testkit.Open(t)
	tn := tenancy.MustParse("00000000-0000-4000-8000-000000000578")
	testkit.CreateTenant(t, db, tn, "prune-release")
	err := db.InTenant(t.Context(), tn, func(c *store.TenantTx) error {
		now := testkit.Now
		if _, err := ingest.Discovery(c, now, []*connectors.DiscoveryResult{pruneRead("", nil, true)}, false); err != nil {
			return err
		}
		st, err := ingest.Discovery(c, now.Add(time.Hour), []*connectors.DiscoveryResult{pruneRead("", nil, true, dropN("s1", 7)...)}, false)
		if err != nil {
			return err
		}
		if len(st.HeldPrunes) != 1 || len(st.HeldPrunes[0].Edges) != 7 {
			t.Fatalf("held = %+v", st.HeldPrunes)
		}
		items, err := c.DeletionHoldItems(st.HeldPrunes[0].HoldID)
		if err != nil || len(items) != 7 {
			t.Fatalf("items = %d, err %v", len(items), err)
		}
		for i, it := range items {
			out, _, err := ingest.ReleaseEdge(c, now.Add(2*time.Hour), it)
			if err != nil || out != deleteguard.ItemReleased {
				t.Fatalf("release %d: %q, %v", i, out, err)
			}
		}
		if n, _ := c.CountEdges(); n != allEdges-7 {
			t.Errorf("%d edges after release, want %d", n, allEdges-7)
		}
		if out, _, err := ingest.ReleaseEdge(c, now.Add(2*time.Hour), items[0]); err != nil || out != deleteguard.ItemGone {
			t.Errorf("second release: %q, %v", out, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
