package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// hrEdgeFeed is a read of n accounts each granted one permission; withEdges false is a complete read that
// lists no grant at all.
func hrEdgeFeed(n int, withEdges bool) *connectors.DiscoveryResult {
	r := &connectors.DiscoveryResult{System: "hr", EdgeSnapshotOf: []string{"hr"}}
	r.Resources = append(r.Resources, connectors.ResourceRecord{System: "hr", ExternalID: "vault", Name: "vault", Kind: "azure_subscription"})
	r.Permissions = append(r.Permissions, connectors.PermissionRecord{System: "hr", ExternalID: "vault|owner", Action: "Owner", ResourceExternalID: "vault"})
	for i := 0; i < n; i++ {
		x := fmt.Sprintf("hr-%02d", i)
		r.Accounts = append(r.Accounts, connectors.AccountRecord{System: "hr", ExternalID: x, Username: x, Status: "active"})
		if withEdges {
			r.Edges = append(r.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: "hr", ExternalID: x},
				Dst: connectors.Ref{Kind: "perm", System: "hr", ExternalID: "vault|owner"}, Relation: "direct_grant"})
		}
	}
	return r
}

// A sync whose complete read lists no grant holds the edge removals (edge_prune items). The admin whose sync
// made the hold cannot release it (403 same_actor, the edges stay); a second admin can, and the release removes
// the held edges and is audited (#577).
func TestDeletionGuardAPI_EdgePruneHoldIsReleasedBySecondAdmin(t *testing.T) {
	const n = 30
	f := storetest.TwoTenants(t)
	feed := &swappableFeed{}
	srv := newIsolationServerWith(f, func(c *Config) {
		c.Connectors = func(time.Time) ([]connectors.Connector, error) { return []connectors.Connector{feed}, nil }
	})
	e := &privEnv{t: t, f: f, srv: srv}
	queuer := e.as("queuer", []auth.Role{auth.RoleTenantAdmin, auth.RolePolicyAdmin}, nil)
	other := e.as("other", []auth.Role{auth.RoleTenantAdmin}, nil)
	edges := func() int {
		t.Helper()
		var c int
		if err := f.DB.ReadTenant(t.Context(), f.B.ID, func(tx *store.TenantTx) (err error) { c, err = tx.CountEdges(); return }); err != nil {
			t.Fatal(err)
		}
		return c
	}

	feed.res.Store(hrEdgeFeed(n, true))
	queuer.call("POST", "/api/connectors/sync", "", 200)
	base := edges()
	if base < n {
		t.Fatalf("seeded %d edges, want at least %d", base, n)
	}
	feed.res.Store(hrEdgeFeed(n, false))
	queuer.call("POST", "/api/connectors/sync", "", 200)
	if got := edges(); got != base {
		t.Fatalf("%d edges after the held sync, want %d: nothing is pruned before the release", got, base)
	}

	holds := queuer.call("GET", "/api/admin/deletion-holds?status=held", "", 200)["holds"].([]any)
	var id string
	for _, h := range holds {
		if m := h.(map[string]any); m["item_count"] == float64(n) {
			id = m["id"].(string)
		}
	}
	if id == "" {
		t.Fatalf("no edge_prune hold in %v", holds)
	}
	one := queuer.call("GET", "/api/admin/deletion-holds/"+id, "", 200)
	if its := one["items"].([]any); len(its) != n || its[0].(map[string]any)["kind"] != "edge_prune" {
		t.Fatalf("hold items = %v", one["items"])
	}

	if got := queuer.call("POST", "/api/admin/deletion-holds/"+id+"/approve", "", 403); got["error"] != "same_actor" {
		t.Errorf("self-approval = %v", got)
	}
	if got := edges(); got != base {
		t.Errorf("%d edges after the refused release, want %d", got, base)
	}

	res := other.call("POST", "/api/admin/deletion-holds/"+id+"/approve", "", 200)
	if res["status"] != "released" || res["released"] != float64(n) {
		t.Fatalf("release = %v", res)
	}
	if got := edges(); got != base-n {
		t.Errorf("%d edges after the release, want %d", got, base-n)
	}
	if got := auditActions(t, f, f.B.ID)["deletion_guard.released"]; got != 1 {
		t.Errorf("deletion_guard.released audited %d times, want 1", got)
	}
}
