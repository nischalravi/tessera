package ingest_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// TestSyncRecordsEdgeHistory: a sync that stops reporting an edge closes its
// span at that sync, a later sync that reports it again opens a new span, and
// an edge every sync reports keeps its one span (no churn).
func TestSyncRecordsEdgeHistory(t *testing.T) {
	st, ids := testkit.Tiny(t)
	ctx := context.Background()
	t1, t2 := testkit.Now.Add(24*time.Hour), testkit.Now.Add(48*time.Hour)
	src, dst := graph.Key("account", ids["acct:okta:alice"]), graph.Key("group", ids["group:okta:eng"])

	sync := func(now time.Time, drop bool) {
		t.Helper()
		r, err := connectors.Tiny{Now: testkit.Now}.Discover(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if drop {
			kept := r.Edges[:0]
			for _, e := range r.Edges {
				if !(e.Src.System == "okta" && e.Src.ExternalID == "alice" && e.Dst.ExternalID == "eng") {
					kept = append(kept, e)
				}
			}
			if len(kept) != len(r.Edges)-1 {
				t.Fatalf("dropped %d edges, want 1", len(r.Edges)-len(kept))
			}
			r.Edges = kept
		}
		testkit.Write(t, st, func(c *store.TenantTx) error {
			_, err := ingest.Discovery(c, now, []*connectors.DiscoveryResult{r}, true)
			return err
		})
	}
	sync(t1, true)
	sync(t2, false)

	spans := testkit.Get(t, st, func(c *store.TenantTx) ([]*store.EdgeSpan, error) { return c.EdgeSpans() })
	var alice []*store.EdgeSpan
	for _, s := range spans {
		if s.Src == src && s.Dst == dst {
			alice = append(alice, s)
		}
	}
	if len(alice) != 2 || !alice[0].ValidFrom.Equal(testkit.Now) || alice[0].ValidTo == nil || !alice[0].ValidTo.Equal(t1) ||
		!alice[1].ValidFrom.Equal(t2) || alice[1].ValidTo != nil {
		t.Fatalf("alice's okta grant spans = %+v", alice)
	}
	edges := testkit.Get(t, st, func(c *store.TenantTx) (int, error) { return c.CountEdges() })
	if len(spans) != edges+1 {
		t.Errorf("%d spans for %d edges, want one per edge plus the re-added one", len(spans), edges)
	}
	for _, s := range spans {
		if s.EdgeID == nil || *s.EdgeID == 0 || s.Source != "connector" {
			t.Errorf("span %+v lacks its edge id or source", s)
		}
	}
}
