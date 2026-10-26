package worker_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// scopedConnector reads two scopes of one system, each with a permission granted to 20 principals.
// The read leaves out the first `dropped` principals of each scope (all of them when dropAll).
// partial/read say what the read covered.
type scopedConnector struct {
	connectors.Connector
	partial string
	read    []string
	dropped int
	dropAll bool
}

func (c *scopedConnector) System() string { return "azure-rbac" }
func (c *scopedConnector) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	const sys = "azure-rbac"
	r := &connectors.DiscoveryResult{System: sys, Partial: c.partial, EdgeSnapshotOf: []string{sys}, EdgeScopesRead: c.read}
	for i := 0; i < 20; i++ {
		p := fmt.Sprintf("p%d", i)
		r.Accounts = append(r.Accounts, connectors.AccountRecord{System: sys, ExternalID: p, Username: p, Status: "active"})
	}
	for _, s := range []string{"s1", "s2"} {
		r.Resources = append(r.Resources, connectors.ResourceRecord{System: sys, ExternalID: s, Name: s, Kind: "azure_subscription"})
		r.Permissions = append(r.Permissions, connectors.PermissionRecord{System: sys, ExternalID: s + "|owner", Action: "Owner", ResourceExternalID: s})
		for i := c.dropped; i < 20 && !c.dropAll; i++ {
			p := fmt.Sprintf("p%d", i)
			r.Edges = append(r.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: sys, ExternalID: p},
				Dst: connectors.Ref{Kind: "perm", System: sys, ExternalID: s + "|owner"}, Relation: "direct_grant"})
		}
	}
	return r, nil
}

// TestSyncPrunesRevokedGrantsOnlyInScopesRead: a grant revoked at the source is removed and audited
// (one connectors.edge_pruned event each) after a complete read; after a Partial read only the
// scopes read in full lose edges; a complete read that lists no edge at all, or removes more than
// the deletion guard allows, removes nothing and says so in the run result and the audit log
// (issue #577).
func TestSyncPrunesRevokedGrantsOnlyInScopesRead(t *testing.T) {
	e := newEnv(t)
	sync := func(now time.Time, c *scopedConnector) string {
		t.Helper()
		var held string
		if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
			out, err := worker.RunSync(t.Context(), tx, now, []connectors.Connector{c}, false, "worker")
			for _, kv := range out {
				if kv.Key == "held_edges" {
					held = fmt.Sprint(kv.Value)
				}
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return held
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
	sync(testkit.Now, &scopedConnector{})
	if n, _ := state(); n != 40 {
		t.Fatalf("seeded %d edges, want 40", n)
	}
	// scope s2 could not be read: only s1's revoked grant goes
	sync(testkit.Now.Add(time.Hour), &scopedConnector{partial: "1 of 2 scopes could not be read", read: []string{"s1"}, dropped: 1})
	if n, p := state(); n != 39 || p != 1 {
		t.Fatalf("after the partial read: %d edges, %d prune events, want 39 and 1", n, p)
	}
	// a complete read that lists no edge at all is held, not applied
	if h := sync(testkit.Now.Add(2*time.Hour), &scopedConnector{dropAll: true}); h != "39" {
		t.Fatalf("held_edges = %q, want 39", h)
	}
	if n, p := state(); n != 39 || p != 1 {
		t.Fatalf("after the empty read: %d edges, %d prune events, want 39 and 1", n, p)
	}
	if got := len(e.audit(t, tenantA, "connectors.edge_prune_held")); got != 1 {
		t.Fatalf("%d edge_prune_held events, want 1", got)
	}
	// a complete read that no longer reports a few grants removes them
	sync(testkit.Now.Add(3*time.Hour), &scopedConnector{dropped: 1})
	if n, p := state(); n != 38 || p != 2 {
		t.Fatalf("after the complete read: %d edges, %d prune events, want 38 and 2", n, p)
	}
}
