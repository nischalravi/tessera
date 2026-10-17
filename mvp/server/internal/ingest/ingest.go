// Package ingest loads connector output into the database.
//
// Ingestion is phased across all connectors so cross-system references
// resolve (e.g. an Okta group -> AWS role edge emitted by the AWS connector):
//
//	identities -> resources -> permissions -> groups -> accounts
//	-> edges -> secrets -> delegations -> events
//
// Every phase is an idempotent upsert keyed on the natural key, scoped to the
// tenant of the transaction it runs in.
package ingest

import (
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

type key struct{ kind, system, xid string }

// Resolver maps natural keys to database ids.
type Resolver struct {
	c               *store.TenantTx
	identityByXID   map[string]int64
	identityByEmail map[string]int64
	ids             map[key]int64
	// survivor maps a merged identity to the one it was merged into: a
	// connector reference to it resolves to the survivor (issue #160).
	survivor map[int64]int64
	// pins are reviewers' account decisions (account_links), keyed by
	// system and external id; sync never overrides them.
	pins map[key]*store.AccountLink
}

// NewResolver loads the current id maps.
func NewResolver(c *store.TenantTx) (*Resolver, error) {
	r := &Resolver{c: c, identityByXID: map[string]int64{}, identityByEmail: map[string]int64{}, ids: map[key]int64{},
		pins: map[key]*store.AccountLink{}}
	return r, r.Refresh()
}

// Refresh reloads the id maps from the database.
func (r *Resolver) Refresh() error {
	idents, err := r.c.Identities()
	if err != nil {
		return err
	}
	for _, i := range idents {
		r.identityByXID[i.ExternalID] = i.ID
		if i.Email != nil && *i.Email != "" {
			r.identityByEmail[strings.ToLower(*i.Email)] = i.ID
		}
	}
	accts, err := r.c.Accounts()
	if err != nil {
		return err
	}
	for _, a := range accts {
		r.ids[key{"account", a.System, a.ExternalID}] = a.ID
	}
	if r.survivor, err = r.c.MergeSurvivors(); err != nil {
		return err
	}
	links, err := r.c.AccountLinks()
	if err != nil {
		return err
	}
	byID := make(map[int64]*store.Account, len(accts))
	for _, a := range accts {
		byID[a.ID] = a
	}
	for _, l := range links {
		if a := byID[l.AccountID]; a != nil {
			r.pins[key{"account", a.System, a.ExternalID}] = l
		}
	}
	groups, err := r.c.Groups()
	if err != nil {
		return err
	}
	for _, g := range groups {
		r.ids[key{"group", g.System, g.ExternalID}] = g.ID
	}
	perms, err := r.c.Permissions()
	if err != nil {
		return err
	}
	for _, p := range perms {
		r.ids[key{"perm", p.System, p.ExternalID}] = p.ID
	}
	res, err := r.c.Resources()
	if err != nil {
		return err
	}
	for _, x := range res {
		r.ids[key{"resource", x.System, x.ExternalID}] = x.ID
	}
	return nil
}

// Identity resolves an identity reference by external id, then email.
func (r *Resolver) Identity(ref *connectors.IdentityRef) *int64 {
	if ref == nil {
		return nil
	}
	if ref.ExternalID != "" {
		if id, ok := r.identityByXID[ref.ExternalID]; ok {
			return r.live(id)
		}
	}
	if ref.Email != "" {
		if id, ok := r.identityByEmail[strings.ToLower(ref.Email)]; ok {
			return r.live(id)
		}
	}
	return nil
}

// IdentityRefOf resolves an identity's manager or owner reference. A
// reference to an identity merged into this one keeps pointing at the merged
// identity, as the merge left it: no one becomes their own manager or owner.
func (r *Resolver) IdentityRefOf(selfXID string, ref *connectors.IdentityRef) *int64 {
	id := r.Identity(ref)
	if self, ok := r.identityByXID[selfXID]; ok && id != nil && *id == self {
		if raw, ok := r.identityByXID[ref.ExternalID]; ok && raw != self {
			return &raw
		}
		return nil
	}
	return id
}

// live follows a merge to the surviving identity.
func (r *Resolver) live(id int64) *int64 {
	if s, ok := r.survivor[id]; ok {
		id = s
	}
	return &id
}

// AccountIdentity is the identity an account belongs to: a reviewer's
// pinned decision if there is one, else the connector's reference.
func (r *Resolver) AccountIdentity(system, xid string, ref *connectors.IdentityRef) *int64 {
	if l := r.pins[key{"account", system, xid}]; l != nil {
		if l.IdentityID == nil {
			return nil
		}
		return r.live(*l.IdentityID)
	}
	return r.Identity(ref)
}

// Node returns the graph node key ("group:7") for a ref, or "".
func (r *Resolver) Node(ref connectors.Ref) string {
	if id, ok := r.ids[key{ref.Kind, ref.System, ref.ExternalID}]; ok {
		return fmt.Sprintf("%s:%d", ref.Kind, id)
	}
	return ""
}

// ID returns the id of an object by kind/system/external id.
func (r *Resolver) ID(kind, system, xid string) (int64, bool) {
	id, ok := r.ids[key{kind, system, xid}]
	return id, ok
}

// DiscoveryStats counts records ingested per type (keys in API order).
type DiscoveryStats struct {
	Identities, Resources, Permissions, Groups, Accounts, Edges, Secrets, Delegations int
}

// Object renders the stats as an ordered JSON object.
func (s DiscoveryStats) Object() ojson.Object {
	return ojson.Object{{Key: "identities", Value: s.Identities}, {Key: "resources", Value: s.Resources},
		{Key: "permissions", Value: s.Permissions}, {Key: "groups", Value: s.Groups}, {Key: "accounts", Value: s.Accounts},
		{Key: "edges", Value: s.Edges}, {Key: "secrets", Value: s.Secrets}, {Key: "delegations", Value: s.Delegations}}
}

// Discovery upserts discovery results. pruneEdges deletes connector edges
// that no connector reported any more.
func Discovery(c *store.TenantTx, now time.Time, results []*connectors.DiscoveryResult, pruneEdges bool) (DiscoveryStats, error) {
	var st DiscoveryStats
	// 1. identities (two passes so manager/owner refs resolve)
	for _, r := range results {
		for _, rec := range r.Identities {
			if err := c.UpsertIdentity(&store.Identity{ExternalID: rec.ExternalID, Name: rec.Name, Email: rec.Email,
				Type: rec.Type, Department: rec.Department, Title: rec.Title, Status: defaultStr(rec.Status, "active"),
				Description: rec.Description, HiredAt: rec.HiredAt, TerminatedAt: rec.TerminatedAt, CreatedAt: now}); err != nil {
				return st, err
			}
			st.Identities++
		}
	}
	res, err := NewResolver(c)
	if err != nil {
		return st, err
	}
	for _, r := range results {
		for _, rec := range r.Identities {
			if err := c.SetIdentityRefsByExternalID(rec.ExternalID, res.IdentityRefOf(rec.ExternalID, rec.Manager),
				res.IdentityRefOf(rec.ExternalID, rec.Owner)); err != nil {
				return st, err
			}
		}
	}
	// 2. resources
	for _, r := range results {
		for _, rec := range r.Resources {
			if err := c.UpsertResource(&store.Resource{System: rec.System, ExternalID: rec.ExternalID, Name: rec.Name,
				Kind: rec.Kind, Environment: rec.Environment, Tags: rec.Tags}); err != nil {
				return st, err
			}
			st.Resources++
		}
	}
	if err := res.Refresh(); err != nil {
		return st, err
	}
	// 3. permissions
	for _, r := range results {
		for _, rec := range r.Permissions {
			rid, ok := res.ID("resource", rec.System, rec.ResourceExternalID)
			if !ok {
				return st, fmt.Errorf("permission %s references unknown resource %s", rec.ExternalID, rec.ResourceExternalID)
			}
			if err := c.UpsertPermission(&store.Permission{System: rec.System, ExternalID: rec.ExternalID, Action: rec.Action,
				ResourceID: rid, Privileged: rec.Privileged}); err != nil {
				return st, err
			}
			st.Permissions++
		}
	}
	// 4. groups
	for _, r := range results {
		for _, rec := range r.Groups {
			if err := c.UpsertGroup(&store.Group{System: rec.System, ExternalID: rec.ExternalID, Name: rec.Name,
				Kind: defaultStr(rec.Kind, "group"), Privileged: rec.Privileged, Requestable: rec.Requestable,
				Description: rec.Description}); err != nil {
				return st, err
			}
			st.Groups++
		}
	}
	// 5. accounts
	for _, r := range results {
		for _, rec := range r.Accounts {
			if err := c.UpsertAccount(&store.Account{System: rec.System, ExternalID: rec.ExternalID, Username: rec.Username,
				IdentityID: res.AccountIdentity(rec.System, rec.ExternalID, rec.Identity), Kind: defaultStr(rec.Kind, "user"), Status: defaultStr(rec.Status, "active"),
				CreatedAt: rec.CreatedAt, LastLoginAt: rec.LastLoginAt}); err != nil {
				return st, err
			}
			st.Accounts++
		}
	}
	if err := res.Refresh(); err != nil {
		return st, err
	}
	// 6. edges
	seen := map[[2]string]bool{}
	for _, r := range results {
		for _, rec := range r.Edges {
			src, dst := res.Node(rec.Src), res.Node(rec.Dst)
			if src == "" || dst == "" {
				return st, fmt.Errorf("unresolved edge %v -> %v", rec.Src, rec.Dst)
			}
			seen[[2]string{src, dst}] = true
			if ev := rec.Evaluation; ev != nil {
				if _, err := c.UpsertEvaluatorEdge(src, dst, rec.Relation, now,
					store.EdgeEvaluation{ExplanationID: ev.ExplanationID, Outcome: ev.Outcome, Fidelity: ev.Fidelity}); err != nil {
					return st, err
				}
			} else if err := c.UpsertConnectorEdge(src, dst, rec.Relation, now); err != nil {
				return st, err
			}
			st.Edges++
		}
	}
	if pruneEdges {
		edges, err := c.Edges()
		if err != nil {
			return st, err
		}
		for _, e := range edges {
			if (e.Source == "connector" || e.Source == store.EdgeSourceEvaluator) && !seen[[2]string{e.Src, e.Dst}] {
				if err := c.DeleteEdge(e.ID); err != nil {
					return st, err
				}
			}
		}
	}
	// 7. secrets
	for _, r := range results {
		for _, rec := range r.Secrets {
			var aid *int64
			if id, ok := res.ID("account", rec.Account.System, rec.Account.ExternalID); ok {
				aid = &id
			}
			if err := c.UpsertSecret(&store.Secret{System: rec.System, ExternalID: rec.ExternalID, Kind: rec.Kind,
				Name: rec.Name, CreatedAt: rec.CreatedAt, LastRotatedAt: rec.LastRotatedAt, LastUsedAt: rec.LastUsedAt},
				aid); err != nil {
				return st, err
			}
			st.Secrets++
		}
	}
	// 8. delegations (replace wholesale, this tenant only: the Python MVP's
	// unscoped bulk delete would have removed every tenant's delegations)
	if _, err := c.DeleteAgentDelegations(); err != nil {
		return st, err
	}
	var dels []store.Delegation
	for _, r := range results {
		for _, rec := range r.Delegations {
			agent, principal := res.Identity(&rec.Agent), res.Identity(&rec.Principal)
			if agent == nil || principal == nil {
				return st, fmt.Errorf("unresolved delegation %v -> %v", rec.Agent, rec.Principal)
			}
			dels = append(dels, store.Delegation{AgentID: *agent, PrincipalID: *principal, Scopes: rec.Scopes,
				CreatedAt: now, ExpiresAt: rec.ExpiresAt})
		}
	}
	if err := c.InsertDelegations(dels); err != nil {
		return st, err
	}
	st.Delegations = len(dels)
	return st, nil
}

// EventStats counts ingested events.
type EventStats struct{ Usage, Hris, Skipped int }

// usageBatch is how many usage events are buffered before a bulk insert.
const usageBatch = 1000

// Events ingests a stream of usage and HRIS events.
func Events(c *store.TenantTx, stream func(yield func(connectors.Event) error) error) (EventStats, error) {
	var st EventStats
	res, err := NewResolver(c)
	if err != nil {
		return st, err
	}
	var usage []store.UsageEvent
	flush := func() error {
		if len(usage) == 0 {
			return nil
		}
		err := c.InsertUsageEvents(usage)
		usage = usage[:0]
		return err
	}
	err = stream(func(ev connectors.Event) error {
		switch e := ev.(type) {
		case *connectors.UsageRecord:
			iid := res.Identity(&e.Identity)
			pid, ok := res.ID("perm", e.Permission.System, e.Permission.ExternalID)
			if iid == nil || !ok {
				st.Skipped++
				return nil
			}
			var aid *int64
			if e.Account != nil {
				if id, ok := res.ID("account", e.Account.System, e.Account.ExternalID); ok {
					aid = &id
				}
			}
			usage = append(usage, store.UsageEvent{IdentityID: *iid, PermissionID: pid, AccountID: aid, Day: e.Day, Count: e.Count})
			st.Usage++
			if len(usage) >= usageBatch {
				return flush()
			}
		case *connectors.HrisEventRecord:
			payload := e.Payload
			if payload == nil {
				payload = ojson.Object{}
			}
			status := "pending"
			// historical events were already handled by the legacy (manual) process
			if h, ok := payload.Get("historical"); ok && truthy(h) {
				status = "executed"
			}
			if err := c.UpsertHrisEvent(&store.HrisEvent{ExternalID: e.ExternalID, Type: e.Type,
				IdentityID: res.Identity(e.Identity), Payload: payload, EffectiveAt: e.EffectiveAt, Status: status}); err != nil {
				return err
			}
			st.Hris++
		}
		return nil
	})
	if err != nil {
		return st, err
	}
	return st, flush()
}

// SyncStats is the result of a full sync.
type SyncStats struct {
	Discovery DiscoveryStats
	Events    EventStats
}

// Sync runs discovery and event ingestion for the connectors.
func Sync(c *store.TenantTx, now time.Time, conns []connectors.Connector, since *time.Time) (SyncStats, error) {
	var out SyncStats
	var results []*connectors.DiscoveryResult
	for _, cn := range conns {
		r, err := cn.Discover(c.Context())
		if err != nil {
			return out, fmt.Errorf("%s: discover: %w", cn.System(), err)
		}
		results = append(results, r)
	}
	d, err := Discovery(c, now, results, true)
	if err != nil {
		return out, err
	}
	out.Discovery = d
	e, err := Events(c, func(yield func(connectors.Event) error) error {
		for _, cn := range conns {
			if err := cn.StreamEvents(c.Context(), since, yield); err != nil {
				return fmt.Errorf("%s: events: %w", cn.System(), err)
			}
		}
		return nil
	})
	out.Events = e
	return out, err
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case float64:
		return x != 0
	}
	return true
}
