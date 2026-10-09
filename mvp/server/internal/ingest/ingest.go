// Package ingest loads connector output into the database.
//
// Ingestion is phased across all connectors so cross-system references
// resolve (e.g. an Okta group -> AWS role edge emitted by the AWS connector):
//
//	identities -> resources -> permissions -> groups -> accounts
//	-> edges -> secrets -> delegations -> events
//
// Every phase is an idempotent upsert keyed on the natural key.
package ingest

import (
	"database/sql"
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
	c               *store.Conn
	identityByXID   map[string]int64
	identityByEmail map[string]int64
	ids             map[key]int64
}

// NewResolver loads the current id maps.
func NewResolver(c *store.Conn) (*Resolver, error) {
	r := &Resolver{c: c, identityByXID: map[string]int64{}, identityByEmail: map[string]int64{}, ids: map[key]int64{}}
	return r, r.Refresh()
}

// Refresh reloads the id maps from the database.
func (r *Resolver) Refresh() error {
	err := r.scan("SELECT id, external_id, email FROM identities ORDER BY id", func(rows *sql.Rows) error {
		var id int64
		var xid string
		var email *string
		if err := rows.Scan(&id, &xid, &email); err != nil {
			return err
		}
		r.identityByXID[xid] = id
		if email != nil && *email != "" {
			r.identityByEmail[strings.ToLower(*email)] = id
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, t := range []struct{ table, kind string }{{"accounts", "account"}, {"groups", "group"}, {"permissions", "perm"}, {"resources", "resource"}} {
		// t.table comes from the fixed list above, never from input.
		err := r.scan("SELECT id, system, external_id FROM "+t.table+" ORDER BY id", func(rows *sql.Rows) error {
			var id int64
			var sys, xid string
			if err := rows.Scan(&id, &sys, &xid); err != nil {
				return err
			}
			r.ids[key{t.kind, sys, xid}] = id
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// scan runs query and calls fn per row, closing the rows and reporting the
// first error (scan, iteration or close).
func (r *Resolver) scan(query string, fn func(*sql.Rows) error) (err error) {
	rows, err := r.c.Query(query)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
	}()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Identity resolves an identity reference by external id, then email.
func (r *Resolver) Identity(ref *connectors.IdentityRef) *int64 {
	if ref == nil {
		return nil
	}
	if ref.ExternalID != "" {
		if id, ok := r.identityByXID[ref.ExternalID]; ok {
			return &id
		}
	}
	if ref.Email != "" {
		if id, ok := r.identityByEmail[strings.ToLower(ref.Email)]; ok {
			return &id
		}
	}
	return nil
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

func tags(t []string) (string, error) {
	if t == nil {
		t = []string{}
	}
	return store.JSON(t)
}

// Discovery upserts discovery results. pruneEdges deletes connector edges
// that no connector reported any more.
func Discovery(c *store.Conn, now time.Time, results []*connectors.DiscoveryResult, pruneEdges bool) (DiscoveryStats, error) {
	var st DiscoveryStats
	// 1. identities (two passes so manager/owner refs resolve)
	for _, r := range results {
		for _, rec := range r.Identities {
			if _, err := c.Exec(`INSERT INTO identities (external_id, name, email, type, department, title, status, description,
				hired_at, terminated_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(external_id) DO UPDATE SET name = excluded.name, email = excluded.email, type = excluded.type,
				department = excluded.department, title = excluded.title, status = excluded.status,
				description = excluded.description, hired_at = excluded.hired_at, terminated_at = excluded.terminated_at`,
				rec.ExternalID, rec.Name, store.SP(rec.Email), rec.Type, store.SP(rec.Department), store.SP(rec.Title),
				defaultStr(rec.Status, "active"), store.SP(rec.Description), store.TP(rec.HiredAt), store.TP(rec.TerminatedAt),
				store.T(now)); err != nil {
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
			if _, err := c.Exec("UPDATE identities SET manager_id = ?, owner_id = ? WHERE external_id = ?",
				store.IP(res.Identity(rec.Manager)), store.IP(res.Identity(rec.Owner)), rec.ExternalID); err != nil {
				return st, err
			}
		}
	}
	// 2. resources
	for _, r := range results {
		for _, rec := range r.Resources {
			t, err := tags(rec.Tags)
			if err != nil {
				return st, err
			}
			if _, err := c.Exec(`INSERT INTO resources (system, external_id, name, kind, environment, tags) VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT(system, external_id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
				environment = excluded.environment, tags = excluded.tags`,
				rec.System, rec.ExternalID, rec.Name, rec.Kind, store.SP(rec.Environment), t); err != nil {
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
			if _, err := c.Exec(`INSERT INTO permissions (system, external_id, action, resource_id, privileged) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(system, external_id) DO UPDATE SET action = excluded.action, resource_id = excluded.resource_id,
				privileged = excluded.privileged`, rec.System, rec.ExternalID, rec.Action, rid, store.B(rec.Privileged)); err != nil {
				return st, err
			}
			st.Permissions++
		}
	}
	// 4. groups
	for _, r := range results {
		for _, rec := range r.Groups {
			if _, err := c.Exec(`INSERT INTO groups (system, external_id, name, kind, privileged, requestable, description)
				VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(system, external_id) DO UPDATE SET name = excluded.name,
				kind = excluded.kind, privileged = excluded.privileged, requestable = excluded.requestable,
				description = excluded.description`, rec.System, rec.ExternalID, rec.Name, defaultStr(rec.Kind, "group"),
				store.B(rec.Privileged), store.B(rec.Requestable), store.SP(rec.Description)); err != nil {
				return st, err
			}
			st.Groups++
		}
	}
	// 5. accounts
	for _, r := range results {
		for _, rec := range r.Accounts {
			if _, err := c.Exec(`INSERT INTO accounts (system, external_id, username, identity_id, kind, status, created_at,
				last_login_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(system, external_id) DO UPDATE SET
				username = excluded.username, identity_id = excluded.identity_id, kind = excluded.kind,
				status = excluded.status, created_at = excluded.created_at, last_login_at = excluded.last_login_at`,
				rec.System, rec.ExternalID, rec.Username, store.IP(res.Identity(rec.Identity)), defaultStr(rec.Kind, "user"),
				defaultStr(rec.Status, "active"), store.TP(rec.CreatedAt), store.TP(rec.LastLoginAt)); err != nil {
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
			if _, err := c.Exec(`INSERT INTO grant_edges (src, dst, relation, source, created_at) VALUES (?, ?, ?, 'connector', ?)
				ON CONFLICT(src, dst) DO UPDATE SET relation = excluded.relation`, src, dst, rec.Relation, store.T(now)); err != nil {
				return st, err
			}
			st.Edges++
		}
	}
	if pruneEdges {
		edges, err := c.Edges("WHERE source = 'connector'")
		if err != nil {
			return st, err
		}
		for _, e := range edges {
			if !seen[[2]string{e.Src, e.Dst}] {
				if err := c.DeleteEdge(e.ID); err != nil {
					return st, err
				}
			}
		}
	}
	// 7. secrets
	for _, r := range results {
		for _, rec := range r.Secrets {
			var aid any
			if id, ok := res.ID("account", rec.Account.System, rec.Account.ExternalID); ok {
				aid = id
			}
			if _, err := c.Exec(`INSERT INTO secrets (system, external_id, account_id, kind, name, created_at, last_rotated_at,
				last_used_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active') ON CONFLICT(system, external_id) DO UPDATE SET
				account_id = excluded.account_id, kind = excluded.kind, name = excluded.name, created_at = excluded.created_at,
				last_rotated_at = excluded.last_rotated_at, last_used_at = excluded.last_used_at`,
				rec.System, rec.ExternalID, aid, rec.Kind, rec.Name, store.T(rec.CreatedAt), store.TP(rec.LastRotatedAt),
				store.TP(rec.LastUsedAt)); err != nil {
				return st, err
			}
			st.Secrets++
		}
	}
	// 8. delegations (replace wholesale)
	if _, err := c.Exec("DELETE FROM agent_delegations"); err != nil {
		return st, err
	}
	for _, r := range results {
		for _, rec := range r.Delegations {
			scopes := rec.Scopes
			if scopes == nil {
				scopes = []string{}
			}
			s, err := store.JSON(scopes)
			if err != nil {
				return st, err
			}
			if _, err := c.Exec("INSERT INTO agent_delegations (agent_id, principal_id, scopes, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
				store.IP(res.Identity(&rec.Agent)), store.IP(res.Identity(&rec.Principal)), s, store.T(now), store.TP(rec.ExpiresAt)); err != nil {
				return st, err
			}
			st.Delegations++
		}
	}
	return st, nil
}

// EventStats counts ingested events.
type EventStats struct{ Usage, Hris, Skipped int }

// Events ingests a stream of usage and HRIS events.
func Events(c *store.Conn, stream func(yield func(connectors.Event) error) error) (EventStats, error) {
	var st EventStats
	res, err := NewResolver(c)
	if err != nil {
		return st, err
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
			var aid any
			if e.Account != nil {
				if id, ok := res.ID("account", e.Account.System, e.Account.ExternalID); ok {
					aid = id
				}
			}
			if _, err := c.Exec("INSERT INTO usage_events (identity_id, permission_id, account_id, day, count) VALUES (?, ?, ?, ?, ?)",
				*iid, pid, aid, store.T(e.Day), e.Count); err != nil {
				return err
			}
			st.Usage++
		case *connectors.HrisEventRecord:
			payload := e.Payload
			if payload == nil {
				payload = ojson.Object{}
			}
			p, err := store.JSON(payload)
			if err != nil {
				return err
			}
			status := "pending"
			// historical events were already handled by the legacy (manual) process
			if h, ok := payload.Get("historical"); ok && truthy(h) {
				status = "executed"
			}
			if _, err := c.Exec(`INSERT INTO hris_events (external_id, type, identity_id, payload, effective_at, status)
				VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(external_id) DO UPDATE SET type = excluded.type,
				identity_id = excluded.identity_id, payload = excluded.payload, effective_at = excluded.effective_at,
				status = excluded.status`, e.ExternalID, e.Type, store.IP(res.Identity(e.Identity)), p, store.T(e.EffectiveAt), status); err != nil {
				return err
			}
			st.Hris++
		}
		return nil
	})
	return st, err
}

// SyncStats is the result of a full sync.
type SyncStats struct {
	Discovery DiscoveryStats
	Events    EventStats
}

// Sync runs discovery and event ingestion for the connectors.
func Sync(c *store.Conn, now time.Time, conns []connectors.Connector, since *time.Time) (SyncStats, error) {
	var out SyncStats
	var results []*connectors.DiscoveryResult
	for _, cn := range conns {
		r, err := cn.Discover(c.Ctx)
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
			if err := cn.StreamEvents(c.Ctx, since, yield); err != nil {
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
