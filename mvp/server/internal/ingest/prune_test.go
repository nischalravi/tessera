package ingest_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const (
	pruneSys   = "azure-rbac"
	perScope   = 20 // principals granted in each of the two scopes: 40 edges
	allEdges   = 2 * perScope
	dropMarker = "*"
)

// pruneRead is a read of two scopes (s1, s2), each with one permission granted to perScope
// principals; drop names the "scope/pN" edges the source no longer reports ("*": all of them).
func pruneRead(partial string, scopesRead []string, snapshot bool, drop ...string) *connectors.DiscoveryResult {
	r := &connectors.DiscoveryResult{System: pruneSys, Partial: partial, EdgeScopesRead: scopesRead}
	if snapshot {
		r.EdgeSnapshotOf = []string{pruneSys}
	}
	dropped := map[string]bool{}
	for _, d := range drop {
		dropped[d] = true
	}
	for i := 0; i < perScope; i++ {
		p := fmt.Sprintf("p%d", i)
		r.Accounts = append(r.Accounts, connectors.AccountRecord{System: pruneSys, ExternalID: p, Username: p, Status: "active"})
	}
	for _, s := range []string{"s1", "s2"} {
		r.Resources = append(r.Resources, connectors.ResourceRecord{System: pruneSys, ExternalID: s, Name: s, Kind: "azure_subscription"})
		r.Permissions = append(r.Permissions, connectors.PermissionRecord{System: pruneSys, ExternalID: s + "|owner", Action: "Owner", ResourceExternalID: s})
		for i := 0; i < perScope; i++ {
			p := fmt.Sprintf("p%d", i)
			if dropped[dropMarker] || dropped[s+"/"+p] {
				continue
			}
			r.Edges = append(r.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: pruneSys, ExternalID: p},
				Dst: connectors.Ref{Kind: "perm", System: pruneSys, ExternalID: s + "|owner"}, Relation: "direct_grant"})
		}
	}
	return r
}

func dropN(scope string, n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s/p%d", scope, i))
	}
	return out
}

// TestEdgePruningRespectsPartialReadsAndTheDeletionGuard: a complete read removes the permission
// edges the source no longer reports, under the deletion guard's threshold; a Partial read removes
// them only in the scopes it read in full; a read that does not declare itself a snapshot removes
// none; over the threshold, or when a "complete" read lists no edge, nothing is removed and the
// edges are held (issue #577).
func TestEdgePruningRespectsPartialReadsAndTheDeletionGuard(t *testing.T) {
	cases := []struct {
		name       string
		second     *connectors.DiscoveryResult
		wantEdges  int      // edges left after the second sync
		pruned     []string // scopes of the edges pruned
		heldEdges  int
		wantReason bool // the feed checks said why
	}{
		{"complete read under the threshold prunes", pruneRead("", nil, true, "s1/p0", "s2/p0"), allEdges - 2, []string{"s1", "s2"}, 0, false},
		{"partial read prunes only the scopes read in full", pruneRead("1 of 2 scopes could not be read", []string{"s1"}, true, "s1/p0", "s2/p0"), allEdges - 1, []string{"s1"}, 0, false},
		{"partial read of no scope prunes nothing", pruneRead("failed page", nil, true, "s1/p0", "s2/p0"), allEdges, nil, 0, false},
		{"unlisted scope in a partial read is kept", pruneRead("truncated", []string{"s1", "s9"}, true, "s2/p0", "s2/p1"), allEdges, nil, 0, false},
		{"a read that is no snapshot prunes nothing", pruneRead("", nil, false, "s1/p0", "s2/p0"), allEdges, nil, 0, false},
		{"over the threshold prunes nothing and holds", pruneRead("", nil, true, dropN("s1", 7)...), allEdges, nil, 7, false},
		{"a complete read with no edge at all prunes nothing and holds", pruneRead("", nil, true, dropMarker), allEdges, nil, allEdges, true},
		{"an empty partial read prunes nothing", pruneRead("failed", nil, true, dropMarker), allEdges, nil, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := testkit.Open(t)
			tn := tenancy.MustParse("00000000-0000-4000-8000-000000000577")
			testkit.CreateTenant(t, db, tn, "prune")
			now := testkit.Now
			var st ingest.DiscoveryStats
			var holds int
			err := db.InTenant(t.Context(), tn, func(c *store.TenantTx) error {
				if _, err := ingest.Discovery(c, now, []*connectors.DiscoveryResult{pruneRead("", nil, true)}, false); err != nil {
					return err
				}
				if n, err := c.CountEdges(); err != nil || n != allEdges {
					t.Fatalf("seeded %d edges, err %v", n, err)
				}
				var err error
				st, err = ingest.Discovery(c, now.Add(time.Hour), []*connectors.DiscoveryResult{tc.second}, false)
				if err != nil {
					return err
				}
				n, err := c.CountEdges()
				if n != tc.wantEdges {
					t.Errorf("%d edges left, want %d", n, tc.wantEdges)
				}
				if err != nil {
					return err
				}
				hs, err := c.DeletionHolds("", "", 100, 0)
				holds = len(hs)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(st.Pruned) != len(tc.pruned) {
				t.Fatalf("pruned %+v, want scopes %v", st.Pruned, tc.pruned)
			}
			for i, s := range tc.pruned {
				if st.Pruned[i].Scope != s || st.Pruned[i].System != pruneSys {
					t.Errorf("pruned[%d] = %+v, want scope %s", i, st.Pruned[i], s)
				}
			}
			held := 0
			for _, h := range st.HeldPrunes {
				held += len(h.Edges)
				if tc.wantReason != (len(h.Reasons) > 0) {
					t.Errorf("feed checks = %v, want reason: %v", h.Reasons, tc.wantReason)
				}
				if h.HoldID == "" {
					t.Error("held edges name no hold")
				}
			}
			if held != tc.heldEdges {
				t.Errorf("held %d edges, want %d", held, tc.heldEdges)
			}
			if (tc.heldEdges > 0) != (holds > 0) {
				t.Errorf("%d open holds for %d held edges", holds, tc.heldEdges)
			}
		})
	}
}
