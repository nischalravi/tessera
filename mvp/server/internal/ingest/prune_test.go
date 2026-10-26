package ingest_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const pruneSys = "azure-rbac"

// pruneRead is a read of two scopes (s1, s2), each with one permission granted to alice and bob;
// drop names the "scope/principal" edges the source no longer reports.
func pruneRead(partial string, scopesRead []string, snapshot bool, drop ...string) *connectors.DiscoveryResult {
	r := &connectors.DiscoveryResult{System: pruneSys, Partial: partial, EdgeScopesRead: scopesRead}
	if snapshot {
		r.EdgeSnapshotOf = []string{pruneSys}
	}
	dropped := map[string]bool{}
	for _, d := range drop {
		dropped[d] = true
	}
	for _, p := range []string{"alice", "bob"} {
		r.Accounts = append(r.Accounts, connectors.AccountRecord{System: pruneSys, ExternalID: p, Username: p, Status: "active"})
	}
	for _, s := range []string{"s1", "s2"} {
		r.Resources = append(r.Resources, connectors.ResourceRecord{System: pruneSys, ExternalID: s, Name: s, Kind: "azure_subscription"})
		r.Permissions = append(r.Permissions, connectors.PermissionRecord{System: pruneSys, ExternalID: s + "|owner", Action: "Owner", ResourceExternalID: s})
		for _, p := range []string{"alice", "bob"} {
			if dropped[s+"/"+p] {
				continue
			}
			r.Edges = append(r.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: pruneSys, ExternalID: p},
				Dst: connectors.Ref{Kind: "perm", System: pruneSys, ExternalID: s + "|owner"}, Relation: "direct_grant"})
		}
	}
	return r
}

// TestEdgePruningRespectsPartialReads: a complete read removes the permission edges the source no
// longer reports; a Partial read removes them only in the scopes it read in full; a read that does
// not declare itself a snapshot removes none (issue #577).
func TestEdgePruningRespectsPartialReads(t *testing.T) {
	cases := []struct {
		name     string
		second   *connectors.DiscoveryResult
		wantEdge int      // edges left after the second sync
		pruned   []string // scope/principal pairs pruned
	}{
		{"complete read prunes every scope", pruneRead("", nil, true, "s1/bob", "s2/alice"), 2, []string{"s1", "s2"}},
		{"partial read prunes only the scopes read in full", pruneRead("1 of 2 scopes could not be read", []string{"s1"}, true, "s1/bob", "s2/alice"), 3, []string{"s1"}},
		{"partial read of no scope prunes nothing", pruneRead("failed page", nil, true, "s1/bob", "s2/alice"), 4, nil},
		{"unlisted scope in a partial read is kept", pruneRead("truncated", []string{"s1", "s9"}, true, "s2/alice", "s2/bob"), 4, nil},
		{"a read that is no snapshot prunes nothing", pruneRead("", nil, false, "s1/bob", "s2/alice"), 4, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := testkit.Open(t)
			tn := tenancy.MustParse("00000000-0000-4000-8000-000000000577")
			testkit.CreateTenant(t, db, tn, "prune")
			now := testkit.Now
			var st ingest.DiscoveryStats
			err := db.InTenant(t.Context(), tn, func(c *store.TenantTx) error {
				if _, err := ingest.Discovery(c, now, []*connectors.DiscoveryResult{pruneRead("", nil, true)}, false); err != nil {
					return err
				}
				if n, err := c.CountEdges(); err != nil || n != 4 {
					t.Fatalf("seeded %d edges, err %v", n, err)
				}
				var err error
				st, err = ingest.Discovery(c, now.Add(time.Hour), []*connectors.DiscoveryResult{tc.second}, false)
				if err != nil {
					return err
				}
				n, err := c.CountEdges()
				if n != tc.wantEdge {
					t.Errorf("%d edges left, want %d", n, tc.wantEdge)
				}
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
		})
	}
}
