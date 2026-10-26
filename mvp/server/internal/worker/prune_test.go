package worker_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// scopedConnector reads two scopes of one system, each with a permission; grants says whether the
// read still reports alice's grant on each. partial/read say what the read covered.
type scopedConnector struct {
	connectors.Connector
	partial string
	read    []string
	grants  bool
}

func (c *scopedConnector) System() string { return "azure-rbac" }
func (c *scopedConnector) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	const sys = "azure-rbac"
	r := &connectors.DiscoveryResult{System: sys, Partial: c.partial, EdgeSnapshotOf: []string{sys}, EdgeScopesRead: c.read,
		Accounts: []connectors.AccountRecord{{System: sys, ExternalID: "alice", Username: "alice", Status: "active"}}}
	for _, s := range []string{"s1", "s2"} {
		r.Resources = append(r.Resources, connectors.ResourceRecord{System: sys, ExternalID: s, Name: s, Kind: "azure_subscription"})
		r.Permissions = append(r.Permissions, connectors.PermissionRecord{System: sys, ExternalID: s + "|owner", Action: "Owner", ResourceExternalID: s})
		if c.grants {
			r.Edges = append(r.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: sys, ExternalID: "alice"},
				Dst: connectors.Ref{Kind: "perm", System: sys, ExternalID: s + "|owner"}, Relation: "direct_grant"})
		}
	}
	return r, nil
}

// TestSyncPrunesRevokedGrantsOnlyInScopesRead: a grant revoked at the source is removed and audited
// (one connectors.edge_pruned event each) after a complete read; after a Partial read only the
// scopes read in full lose edges (issue #577).
func TestSyncPrunesRevokedGrantsOnlyInScopesRead(t *testing.T) {
	e := newEnv(t)
	sync := func(now time.Time, c *scopedConnector) {
		t.Helper()
		if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
			_, err := worker.RunSync(t.Context(), tx, now, []connectors.Connector{c}, false, "worker")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	state := func() (edges, pruned int) {
		t.Helper()
		if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) (err error) {
			edges, err = tx.CountEdges()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return edges, len(e.audit(t, tenantA, "connectors.edge_pruned"))
	}
	sync(testkit.Now, &scopedConnector{grants: true})
	if n, _ := state(); n != 2 {
		t.Fatalf("seeded %d edges, want 2", n)
	}
	// scope s2 could not be read: only s1's revoked grant goes
	sync(testkit.Now.Add(time.Hour), &scopedConnector{partial: "1 of 2 scopes could not be read", read: []string{"s1"}})
	if n, p := state(); n != 1 || p != 1 {
		t.Fatalf("after the partial read: %d edges, %d prune events, want 1 and 1", n, p)
	}
	// a complete read that no longer reports the grant removes the rest
	sync(testkit.Now.Add(2*time.Hour), &scopedConnector{})
	if n, p := state(); n != 0 || p != 2 {
		t.Fatalf("after the complete read: %d edges, %d prune events, want 0 and 2", n, p)
	}
}
