package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ItemEdgePrune is the kind of the held item of a permission edge a sync would remove.
const ItemEdgePrune = "edge_prune"

// PrunedEdge is a connector permission edge a sync removed (or, in Held, would have removed but the
// deletion guard held) because a read that covered its scope no longer reported it.
type PrunedEdge struct {
	Src, Dst string
	System   string // the system of the permission
	Scope    string // external id of the resource (scope) the permission is on; "" for none
	Relation string
}

// HeldPrune is what the deletion guard held for one system: its edges stay until an admin releases them.
type HeldPrune struct {
	System  string
	Edges   []PrunedEdge
	Reasons []string // why the feed looked wrong; empty when only the threshold was passed
	HoldID  string
}

// edgeRef is the Ref of a held edge-prune item.
type edgeRef struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

// pruneSnapshots removes the stored connector edges into the permissions of the systems a result
// lists completely (DiscoveryResult.EdgeSnapshotOf) that no result reported this sync (issue #577).
// A complete read covers all of a system's permissions. A Partial read covers only the permissions
// on EdgeScopesRead, the scopes read in full: for any other scope (a denied call, a failed page, a
// truncated list) absence is not evidence that the grant is gone, so its edges stay. Only edges a
// connector wrote are touched; JIT, manual, request, role and evaluator edges are not.
//
// The removals go through the deletion guard under the accounts category, the one the connection's
// deletion-guard settings configure: over the threshold, or when the feed looks wrong (it lists no
// edge, or far fewer than the edges now stored for the covered scopes), nothing is removed and the
// edges are held for an admin (ReleaseEdge), as the account removals of a sync are.
func pruneSnapshots(c *store.TenantTx, now time.Time, results []*connectors.DiscoveryResult, seen map[[2]string]bool) ([]PrunedEdge, []HeldPrune, error) {
	// per system: every scope is covered (complete read), or just these
	type cover struct {
		all      bool
		scopes   map[string]bool
		sourceID string
	}
	covers := map[string]*cover{}
	for _, r := range results {
		for _, sys := range r.EdgeSnapshotOf {
			cv := covers[sys]
			if cv == nil {
				cv = &cover{all: true, scopes: map[string]bool{}}
				covers[sys] = cv
			}
			if r.SourceID != "" {
				cv.sourceID = r.SourceID
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
		return nil, nil, nil
	}
	perms, err := c.Permissions()
	if err != nil {
		return nil, nil, err
	}
	resources, err := c.Resources()
	if err != nil {
		return nil, nil, err
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
		return nil, nil, nil
	}
	edges, err := c.Edges()
	if err != nil {
		return nil, nil, err
	}
	stale := map[string][]PrunedEdge{} // by system
	stored, still := map[string]int{}, map[string]int{}
	for _, e := range edges {
		pi, ok := covered[e.Dst]
		if !ok || e.Source != "connector" {
			continue
		}
		stored[pi.system]++
		if seen[[2]string{e.Src, e.Dst}] {
			still[pi.system]++
			continue
		}
		stale[pi.system] = append(stale[pi.system], PrunedEdge{Src: e.Src, Dst: e.Dst, System: pi.system, Scope: pi.scope, Relation: e.Relation})
	}
	systems := make([]string, 0, len(covers))
	for sys := range covers {
		systems = append(systems, sys)
	}
	sort.Strings(systems)
	conns, err := c.Connections()
	if err != nil {
		return nil, nil, err
	}
	var pruned []PrunedEdge
	var held []HeldPrune
	for _, sys := range systems {
		ref := deleteguard.SourceRef{Kind: deleteguard.SrcConnection, ID: covers[sys].sourceID}
		if ref.ID == "" {
			for _, cn := range conns {
				if cn.System == sys && cn.RetiredAt == nil {
					ref.ID = cn.ID
				}
			}
		}
		corr := suffix("ingest:edges:"+sys, ref.ID)
		// edges the feed lists again are not being removed: withdraw their earlier held items
		if _, err := deleteguard.Relist(c, now, deleteguard.CatAccounts, corr, func(it *store.DeletionHoldItem) bool {
			var k edgeRef
			return it.Kind == ItemEdgePrune && json.Unmarshal([]byte(it.Ref), &k) == nil && seen[[2]string{k.Src, k.Dst}]
		}); err != nil {
			return nil, nil, err
		}
		if len(stale[sys]) == 0 {
			continue
		}
		items := make([]deleteguard.Item, 0, len(stale[sys]))
		byRef := map[string]PrunedEdge{}
		for _, e := range stale[sys] {
			rf, err := json.Marshal(edgeRef{e.Src, e.Dst})
			if err != nil {
				return nil, nil, err
			}
			byRef[string(rf)] = e
			items = append(items, deleteguard.Item{Kind: ItemEdgePrune, Ref: string(rf),
				Label: fmt.Sprintf("grant %s -> %s in %s no longer reported", e.Src, e.Dst, sys)})
		}
		feed := deleteguard.DefaultFeed()
		if ov, err := deleteguard.SourcePolicyOf(c, ref, deleteguard.CatAccounts); err != nil {
			return nil, nil, err
		} else if ov != nil {
			feed = ov.FeedSettings()
		}
		sanity := deleteguard.FeedChecksWith(stored[sys], still[sys], "", feed)
		d, err := deleteguard.AdmitWith(c, now, deleteguard.Request{Category: deleteguard.CatAccounts, Items: items,
			Source: deleteguard.SourceConnector, SourceID: ref.ID, SourceRef: ref, Correlation: corr, SourceDriven: true,
			Sanity: sanity, PrevCount: stored[sys], NewCount: still[sys]})
		if err != nil {
			return nil, nil, err
		}
		for _, it := range d.Applied {
			e := byRef[it.Ref]
			var k edgeRef
			if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
				return nil, nil, err
			}
			cur, err := c.EdgeBetween(k.Src, k.Dst)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, nil, err
			}
			if err := c.DeleteEdge(cur.ID, now); err != nil {
				return nil, nil, err
			}
			pruned = append(pruned, e)
		}
		if len(d.Held) > 0 {
			h := HeldPrune{System: sys, Reasons: sanity, HoldID: d.HoldID}
			for _, it := range d.Held {
				h.Edges = append(h.Edges, byRef[it.Ref])
			}
			held = append(held, h)
		}
	}
	return pruned, held, nil
}

// ReleaseEdge removes a held edge: the grant a complete read no longer reported, once an admin
// approved the removal. An edge that is back in the source's feed was withdrawn from the hold by
// the sync that saw it (deleteguard.Relist); one that is gone or no longer a connector edge is left.
func ReleaseEdge(tx *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error) {
	var k edgeRef
	if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
		return "", "", fmt.Errorf("ingest: bad held edge: %w", err)
	}
	e, err := tx.EdgeBetween(k.Src, k.Dst)
	if errors.Is(err, store.ErrNotFound) {
		return deleteguard.ItemGone, "the grant no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	if e.Source != "connector" {
		return deleteguard.ItemGone, "the grant is no longer one the connector reported", nil
	}
	if err := tx.DeleteEdge(e.ID, now); err != nil {
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}
