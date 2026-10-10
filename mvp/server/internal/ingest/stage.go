package ingest

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// StageStats counts what a dry run staged.
type StageStats struct {
	Identities, Accounts, Groups, Memberships int
}

// Stage writes a dry run's discovery result into the staging tables of run
// runID (design §6.1). It writes only stg_* tables; nothing here touches the
// live graph, and no code path copies staged rows into live tables
// (TestStage_NoLiveWrites). Only the connection's own system is staged.
func Stage(c *store.TenantTx, runID, system string, res *connectors.DiscoveryResult) (StageStats, error) {
	var st StageStats
	for _, x := range res.Identities {
		attrs := map[string]string{}
		if x.Manager != nil {
			attrs["manager"] = x.Manager.ExternalID
		}
		typ, status := x.Type, x.Status
		if err := c.InsertStagedIdentity(&store.StagedIdentity{RunID: runID, ExternalID: x.ExternalID, Name: x.Name,
			Email: x.Email, Type: &typ, Status: &status, Department: x.Department, HiredAt: x.HiredAt,
			TerminatedAt: x.TerminatedAt, Attributes: attrs}); err != nil {
			return st, err
		}
		st.Identities++
	}
	for _, a := range res.Accounts {
		if a.System != system {
			continue
		}
		if err := c.InsertStagedAccount(&store.StagedAccount{RunID: runID, System: a.System, ExternalID: a.ExternalID,
			Username: a.Username, Kind: defaultStr(a.Kind, "user"), Status: defaultStr(a.Status, "active"),
			CreatedAt: a.CreatedAt, LastLoginAt: a.LastLoginAt, Attributes: a.Attributes}); err != nil {
			return st, err
		}
		st.Accounts++
	}
	for _, g := range res.Groups {
		if g.System != system {
			continue
		}
		if err := c.InsertStagedGroup(&store.StagedGroup{RunID: runID, System: g.System, ExternalID: g.ExternalID,
			Name: g.Name, Kind: defaultStr(g.Kind, "group"), Privileged: g.Privileged, InScope: true}); err != nil {
			return st, err
		}
		st.Groups++
	}
	for _, e := range res.Edges {
		if e.Relation != "member_of" || e.Src.System != system || e.Dst.Kind != "group" || e.Dst.System != system {
			continue
		}
		if e.Src.Kind != "account" && e.Src.Kind != "group" {
			continue
		}
		if err := c.InsertStagedMembership(runID, store.StagedMembership{MemberKind: e.Src.Kind, MemberXID: e.Src.ExternalID,
			GroupXID: e.Dst.ExternalID}); err != nil {
			return st, err
		}
		st.Memberships++
	}
	if res.Stats != nil {
		classes := make([]string, 0, len(res.Stats.Classes))
		for k := range res.Stats.Classes {
			classes = append(classes, k)
		}
		sort.Strings(classes)
		for _, cls := range classes {
			cs := res.Stats.Classes[cls]
			if err := c.InsertAttrStat(runID, store.AttrStat{Class: cls, Attribute: "*", Total: cs.Total, Present: cs.Total}); err != nil {
				return st, err
			}
			for attr, s := range cs.Attributes {
				if err := c.InsertAttrStat(runID, store.AttrStat{Class: cls, Attribute: attr, Total: cs.Total, Present: s.Present,
					Distinct: s.Distinct}); err != nil {
					return st, err
				}
			}
		}
	}
	return st, nil
}

// SyncActive syncs live connections into the graph. It accepts only
// readiness.ActiveConnection values, which only package readiness can
// construct (for revisions that passed every gate), so a draft connection
// cannot be synced into the live graph by mistake (§4.4).
//
// The sync is additive (no edge pruning: other connections' edges stay), and
// memberships in groups outside the connection's scope are left out: the dry
// run reported them (RF-05).
func SyncActive(c *store.TenantTx, now time.Time, conns []readiness.ActiveConnection,
	open func(readiness.ActiveConnection) (connectors.Connector, error)) (SyncStats, error) {
	var out SyncStats
	var results []*connectors.DiscoveryResult
	var cs []connectors.Connector
	for _, ac := range conns {
		cn, err := open(ac)
		if err != nil {
			return out, fmt.Errorf("%s: %w", ac.Name(), err)
		}
		r, err := cn.Discover(c.Context())
		if err != nil {
			return out, fmt.Errorf("%s: discover: %w", ac.Name(), err)
		}
		results = append(results, inScope(r))
		cs = append(cs, cn)
	}
	d, err := Discovery(c, now, results, false)
	if err != nil {
		return out, err
	}
	out.Discovery = d
	out.Events, err = Events(c, func(yield func(connectors.Event) error) error {
		for _, cn := range cs {
			if err := cn.StreamEvents(c.Context(), nil, yield); err != nil {
				return fmt.Errorf("%s: events: %w", cn.System(), err)
			}
		}
		return nil
	})
	return out, err
}

// inScope drops memberships whose group is in the connector's own system but
// not in its result (outside the base DNs).
func inScope(r *connectors.DiscoveryResult) *connectors.DiscoveryResult {
	own := map[string]bool{}
	systems := map[string]bool{}
	for _, g := range r.Groups {
		own[g.System+"|"+g.ExternalID] = true
		systems[g.System] = true
	}
	out := *r
	out.Edges = slices.DeleteFunc(slices.Clone(r.Edges), func(e connectors.EdgeRecord) bool {
		return e.Dst.Kind == "group" && systems[e.Dst.System] && !own[e.Dst.System+"|"+e.Dst.ExternalID]
	})
	return &out
}
