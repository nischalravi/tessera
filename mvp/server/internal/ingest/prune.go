package ingest

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// PrunedEdge is a connector permission edge a sync removed because a read that covered its scope
// no longer reported it.
type PrunedEdge struct {
	Src, Dst string
	System   string // the system of the permission
	Scope    string // external id of the resource (scope) the permission is on; "" for none
	Relation string
}

// pruneSnapshots removes the stored connector edges into the permissions of the systems a result
// lists completely (DiscoveryResult.EdgeSnapshotOf) that no result reported this sync (issue #577).
// A complete read covers all of a system's permissions. A Partial read covers only the permissions
// on EdgeScopesRead, the scopes read in full: for any other scope (a denied call, a failed page, a
// truncated list) absence is not evidence that the grant is gone, so its edges stay. Only edges a
// connector wrote are touched; JIT, manual, request, role and evaluator edges are not.
func pruneSnapshots(c *store.TenantTx, now time.Time, results []*connectors.DiscoveryResult, seen map[[2]string]bool) ([]PrunedEdge, error) {
	// per system: every scope is covered (complete read), or just these
	type cover struct {
		all    bool
		scopes map[string]bool
	}
	covers := map[string]*cover{}
	for _, r := range results {
		for _, sys := range r.EdgeSnapshotOf {
			cv := covers[sys]
			if cv == nil {
				cv = &cover{all: true, scopes: map[string]bool{}}
				covers[sys] = cv
			}
			if r.Partial == "" {
				continue
			}
			cv.all = false // a partial result narrows the whole system to the scopes it read in full
			for _, s := range r.EdgeScopesRead {
				cv.scopes[s] = true
			}
		}
	}
	if len(covers) == 0 {
		return nil, nil
	}
	perms, err := c.Permissions()
	if err != nil {
		return nil, err
	}
	resources, err := c.Resources()
	if err != nil {
		return nil, err
	}
	scopeOf := map[int64]string{}
	for _, r := range resources {
		scopeOf[r.ID] = r.ExternalID
	}
	type permInfo struct{ system, scope string }
	covered := map[string]permInfo{}
	for _, p := range perms {
		cv := covers[p.System]
		if cv == nil {
			continue
		}
		scope := scopeOf[p.ResourceID]
		if cv.all || (scope != "" && cv.scopes[scope]) {
			covered[graph.Key("perm", p.ID)] = permInfo{p.System, scope}
		}
	}
	if len(covered) == 0 {
		return nil, nil
	}
	edges, err := c.Edges()
	if err != nil {
		return nil, err
	}
	var out []PrunedEdge
	for _, e := range edges {
		pi, ok := covered[e.Dst]
		if !ok || e.Source != "connector" || seen[[2]string{e.Src, e.Dst}] {
			continue
		}
		if err := c.DeleteEdge(e.ID, now); err != nil {
			return nil, err
		}
		out = append(out, PrunedEdge{Src: e.Src, Dst: e.Dst, System: pi.system, Scope: pi.scope, Relation: e.Relation})
	}
	return out, nil
}
