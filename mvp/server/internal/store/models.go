package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// ---------------------------------------------------------------- values

// T formats a timestamp for storage.
func T(t time.Time) string { return timeutil.DB(t) }

// TP formats an optional timestamp for storage (NULL for nil).
func TP(t *time.Time) any {
	if t == nil {
		return nil
	}
	return timeutil.DB(*t)
}

// SP stores an optional string (NULL for nil).
func SP(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// IP stores an optional integer (NULL for nil).
func IP(i *int64) any {
	if i == nil {
		return nil
	}
	return *i
}

// B stores a boolean.
func B(b bool) int {
	if b {
		return 1
	}
	return 0
}

// JSON encodes a value for a JSON column.
func JSON(v any) (string, error) {
	b, err := ojson.Marshal(v)
	return string(b), err
}

type nullTime struct {
	sql.NullString
}

func (n nullTime) ptr() (*time.Time, error) {
	if !n.Valid {
		return nil, nil
	}
	t, err := timeutil.ParseDB(n.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (n nullTime) val() (time.Time, error) {
	t, err := n.ptr()
	if err != nil || t == nil {
		return time.Time{}, errors.Join(err, errors.New("store: unexpected NULL timestamp"))
	}
	return *t, nil
}

func strp(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	s := n.String
	return &s
}

func intp(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	i := n.Int64
	return &i
}

type scanner interface{ Scan(dest ...any) error }

func collect[T any](c *Conn, scan func(scanner) (*T, error), query string, args ...any) ([]*T, error) {
	rows, err := c.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func one[T any](c *Conn, scan func(scanner) (*T, error), query string, args ...any) (*T, error) {
	v, err := scan(c.QueryRow(query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// ---------------------------------------------------------------- identities

// Identity is a person, service account or AI agent.
type Identity struct {
	ID           int64
	ExternalID   string
	Name         string
	Email        *string
	Type         string
	Department   *string
	Title        *string
	Status       string
	ManagerID    *int64
	OwnerID      *int64
	Source       *string
	Description  *string
	HiredAt      *time.Time
	TerminatedAt *time.Time
	CreatedAt    time.Time
}

const identityCols = `id, external_id, name, email, type, department, title, status, manager_id, owner_id,
	source, description, hired_at, terminated_at, created_at`

func scanIdentity(s scanner) (*Identity, error) {
	var i Identity
	var email, dept, title, source, desc sql.NullString
	var mgr, owner sql.NullInt64
	var hired, term, created nullTime
	if err := s.Scan(&i.ID, &i.ExternalID, &i.Name, &email, &i.Type, &dept, &title, &i.Status, &mgr, &owner,
		&source, &desc, &hired, &term, &created); err != nil {
		return nil, err
	}
	i.Email, i.Department, i.Title, i.Source, i.Description = strp(email), strp(dept), strp(title), strp(source), strp(desc)
	i.ManagerID, i.OwnerID = intp(mgr), intp(owner)
	var err error
	if i.HiredAt, err = hired.ptr(); err != nil {
		return nil, err
	}
	if i.TerminatedAt, err = term.ptr(); err != nil {
		return nil, err
	}
	i.CreatedAt, err = created.val()
	return &i, err
}

// Identities returns identities matching an optional WHERE clause, in id order.
func (c *Conn) Identities(where string, args ...any) ([]*Identity, error) {
	return collect(c, scanIdentity, "SELECT "+identityCols+" FROM identities "+where+" ORDER BY id", args...)
}

// Identity returns one identity by id (ErrNotFound if missing).
func (c *Conn) Identity(id int64) (*Identity, error) {
	return one(c, scanIdentity, "SELECT "+identityCols+" FROM identities WHERE id = ?", id)
}

// IdentityMap returns all identities keyed by id plus the id order.
func (c *Conn) IdentityMap() (map[int64]*Identity, []*Identity, error) {
	all, err := c.Identities("")
	if err != nil {
		return nil, nil, err
	}
	m := make(map[int64]*Identity, len(all))
	for _, i := range all {
		m[i.ID] = i
	}
	return m, all, nil
}

// ---------------------------------------------------------------- accounts

// Account is an account in one system.
type Account struct {
	ID          int64
	System      string
	ExternalID  string
	IdentityID  *int64
	Username    string
	Kind        string
	Status      string
	CreatedAt   *time.Time
	LastLoginAt *time.Time
}

const accountCols = `id, system, external_id, identity_id, username, kind, status, created_at, last_login_at`

func scanAccount(s scanner) (*Account, error) {
	var a Account
	var iid sql.NullInt64
	var created, last nullTime
	if err := s.Scan(&a.ID, &a.System, &a.ExternalID, &iid, &a.Username, &a.Kind, &a.Status, &created, &last); err != nil {
		return nil, err
	}
	a.IdentityID = intp(iid)
	var err error
	if a.CreatedAt, err = created.ptr(); err != nil {
		return nil, err
	}
	a.LastLoginAt, err = last.ptr()
	return &a, err
}

// Accounts returns accounts matching an optional WHERE clause; order defaults to id.
func (c *Conn) Accounts(where string, args ...any) ([]*Account, error) {
	return collect(c, scanAccount, "SELECT "+accountCols+" FROM accounts "+where+" ORDER BY id", args...)
}

// AccountsOrdered returns accounts with an explicit WHERE and ORDER BY tail.
func (c *Conn) AccountsOrdered(tail string, args ...any) ([]*Account, error) {
	return collect(c, scanAccount, "SELECT "+accountCols+" FROM accounts "+tail, args...)
}

// Account returns one account by id.
func (c *Conn) Account(id int64) (*Account, error) {
	return one(c, scanAccount, "SELECT "+accountCols+" FROM accounts WHERE id = ?", id)
}

// IdentityAccounts returns an identity's accounts in id order.
func (c *Conn) IdentityAccounts(identityID int64) ([]*Account, error) {
	return c.Accounts("WHERE identity_id = ?", identityID)
}

// ---------------------------------------------------------------- groups

// Group is a group, team, role or security group.
type Group struct {
	ID          int64
	System      string
	ExternalID  string
	Name        string
	Kind        string
	Privileged  bool
	Requestable bool
	Description *string
}

const groupCols = `id, system, external_id, name, kind, privileged, requestable, description`

func scanGroup(s scanner) (*Group, error) {
	var g Group
	var desc sql.NullString
	if err := s.Scan(&g.ID, &g.System, &g.ExternalID, &g.Name, &g.Kind, &g.Privileged, &g.Requestable, &desc); err != nil {
		return nil, err
	}
	g.Description = strp(desc)
	return &g, nil
}

// Groups returns groups with a WHERE/ORDER BY tail.
func (c *Conn) Groups(tail string, args ...any) ([]*Group, error) {
	return collect(c, scanGroup, "SELECT "+groupCols+" FROM groups "+tail, args...)
}

// Group returns one group by id.
func (c *Conn) Group(id int64) (*Group, error) {
	return one(c, scanGroup, "SELECT "+groupCols+" FROM groups WHERE id = ?", id)
}

// GroupByXID returns the first group with the system and external id.
func (c *Conn) GroupByXID(system, xid string) (*Group, error) {
	return one(c, scanGroup, "SELECT "+groupCols+" FROM groups WHERE system = ? AND external_id = ? ORDER BY id LIMIT 1", system, xid)
}

// ---------------------------------------------------------------- resources & permissions

// Resource is something permissions act on.
type Resource struct {
	ID          int64
	System      string
	ExternalID  string
	Name        string
	Kind        string
	Environment *string
	Tags        []string
}

const resourceCols = `id, system, external_id, name, kind, environment, tags`

func scanResource(s scanner) (*Resource, error) {
	var r Resource
	var env sql.NullString
	var tags string
	if err := s.Scan(&r.ID, &r.System, &r.ExternalID, &r.Name, &r.Kind, &env, &tags); err != nil {
		return nil, err
	}
	r.Environment = strp(env)
	if err := json.Unmarshal([]byte(tags), &r.Tags); err != nil {
		return nil, fmt.Errorf("store: resource %d tags: %w", r.ID, err)
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
	return &r, nil
}

// Resources returns resources with a WHERE/ORDER BY tail.
func (c *Conn) Resources(tail string, args ...any) ([]*Resource, error) {
	return collect(c, scanResource, "SELECT "+resourceCols+" FROM resources "+tail, args...)
}

// Permission is an action on a resource.
type Permission struct {
	ID         int64
	System     string
	ExternalID string
	Action     string
	ResourceID int64
	Privileged bool
}

const permissionCols = `id, system, external_id, action, resource_id, privileged`

func scanPermission(s scanner) (*Permission, error) {
	var p Permission
	if err := s.Scan(&p.ID, &p.System, &p.ExternalID, &p.Action, &p.ResourceID, &p.Privileged); err != nil {
		return nil, err
	}
	return &p, nil
}

// Permissions returns permissions with a WHERE/ORDER BY tail.
func (c *Conn) Permissions(tail string, args ...any) ([]*Permission, error) {
	return collect(c, scanPermission, "SELECT "+permissionCols+" FROM permissions "+tail, args...)
}

// Permission returns one permission by id.
func (c *Conn) Permission(id int64) (*Permission, error) {
	return one(c, scanPermission, "SELECT "+permissionCols+" FROM permissions WHERE id = ?", id)
}

// ResourceName returns a resource's name.
func (c *Conn) ResourceName(id int64) (string, error) {
	var name string
	err := c.QueryRow("SELECT name FROM resources WHERE id = ?", id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}

// ---------------------------------------------------------------- grant edges

// GrantEdge is a grant between two graph nodes, e.g. account:3 -> group:7.
type GrantEdge struct {
	ID        int64
	Src, Dst  string
	Relation  string
	Source    string // connector | jit | manual
	ExpiresAt *time.Time
	CreatedAt time.Time
}

const edgeCols = `id, src, dst, relation, source, expires_at, created_at`

func scanEdge(s scanner) (*GrantEdge, error) {
	var e GrantEdge
	var exp, created nullTime
	if err := s.Scan(&e.ID, &e.Src, &e.Dst, &e.Relation, &e.Source, &exp, &created); err != nil {
		return nil, err
	}
	var err error
	if e.ExpiresAt, err = exp.ptr(); err != nil {
		return nil, err
	}
	e.CreatedAt, err = created.val()
	return &e, err
}

// Edges returns grant edges matching an optional WHERE clause, in id order.
func (c *Conn) Edges(where string, args ...any) ([]*GrantEdge, error) {
	return collect(c, scanEdge, "SELECT "+edgeCols+" FROM grant_edges "+where+" ORDER BY id", args...)
}

// Edge returns one grant edge by id.
func (c *Conn) Edge(id int64) (*GrantEdge, error) {
	return one(c, scanEdge, "SELECT "+edgeCols+" FROM grant_edges WHERE id = ?", id)
}

// EdgeBetween returns the edge src -> dst, if any.
func (c *Conn) EdgeBetween(src, dst string) (*GrantEdge, error) {
	return one(c, scanEdge, "SELECT "+edgeCols+" FROM grant_edges WHERE src = ? AND dst = ? ORDER BY id LIMIT 1", src, dst)
}

// DeleteEdge deletes a grant edge by id.
func (c *Conn) DeleteEdge(id int64) error {
	_, err := c.Exec("DELETE FROM grant_edges WHERE id = ?", id)
	return err
}

// ---------------------------------------------------------------- secrets

// Secret is a credential bound to an account.
type Secret struct {
	ID            int64
	System        string
	ExternalID    string
	AccountID     int64
	Kind          string
	Name          string
	CreatedAt     time.Time
	LastRotatedAt *time.Time
	LastUsedAt    *time.Time
	Status        string
}

const secretCols = `s.id, s.system, s.external_id, s.account_id, s.kind, s.name, s.created_at, s.last_rotated_at,
	s.last_used_at, s.status`

func scanSecret(s scanner) (*Secret, error) {
	var x Secret
	var created, rot, used nullTime
	if err := s.Scan(&x.ID, &x.System, &x.ExternalID, &x.AccountID, &x.Kind, &x.Name, &created, &rot, &used, &x.Status); err != nil {
		return nil, err
	}
	var err error
	if x.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	if x.LastRotatedAt, err = rot.ptr(); err != nil {
		return nil, err
	}
	x.LastUsedAt, err = used.ptr()
	return &x, err
}

// Secrets returns secrets matching an optional WHERE clause (alias s), in id order.
func (c *Conn) Secrets(where string, args ...any) ([]*Secret, error) {
	return collect(c, scanSecret, "SELECT "+secretCols+" FROM secrets s "+where+" ORDER BY s.id", args...)
}

// Secret returns one secret by id.
func (c *Conn) Secret(id int64) (*Secret, error) {
	return one(c, scanSecret, "SELECT "+secretCols+" FROM secrets s WHERE s.id = ?", id)
}

// SecretWithAccount pairs a secret with its account.
type SecretWithAccount struct {
	Secret  *Secret
	Account *Account
}

// SecretsWithAccounts joins secrets to accounts (optional WHERE on aliases s/a), in secret id order.
func (c *Conn) SecretsWithAccounts(where string, args ...any) ([]SecretWithAccount, error) {
	rows, err := c.Query(`SELECT `+secretCols+`, a.id, a.system, a.external_id, a.identity_id, a.username, a.kind,
		a.status, a.created_at, a.last_login_at FROM secrets s JOIN accounts a ON s.account_id = a.id `+where+` ORDER BY s.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretWithAccount
	for rows.Next() {
		var x Secret
		var created, rot, used nullTime
		var a Account
		var iid sql.NullInt64
		var acreated, last nullTime
		if err := rows.Scan(&x.ID, &x.System, &x.ExternalID, &x.AccountID, &x.Kind, &x.Name, &created, &rot, &used, &x.Status,
			&a.ID, &a.System, &a.ExternalID, &iid, &a.Username, &a.Kind, &a.Status, &acreated, &last); err != nil {
			return nil, err
		}
		if x.CreatedAt, err = created.val(); err != nil {
			return nil, err
		}
		if x.LastRotatedAt, err = rot.ptr(); err != nil {
			return nil, err
		}
		if x.LastUsedAt, err = used.ptr(); err != nil {
			return nil, err
		}
		a.IdentityID = intp(iid)
		if a.CreatedAt, err = acreated.ptr(); err != nil {
			return nil, err
		}
		if a.LastLoginAt, err = last.ptr(); err != nil {
			return nil, err
		}
		out = append(out, SecretWithAccount{&x, &a})
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- delegations

// Delegation is an AI agent acting on behalf of a principal with bounded scopes.
type Delegation struct {
	ID          int64
	AgentID     int64
	PrincipalID int64
	Scopes      []string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
}

func scanDelegation(s scanner) (*Delegation, error) {
	var d Delegation
	var scopes string
	var created, exp nullTime
	if err := s.Scan(&d.ID, &d.AgentID, &d.PrincipalID, &scopes, &created, &exp); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopes), &d.Scopes); err != nil {
		return nil, err
	}
	if d.Scopes == nil {
		d.Scopes = []string{}
	}
	var err error
	if d.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	d.ExpiresAt, err = exp.ptr()
	return &d, err
}

// Delegations returns delegations matching an optional WHERE clause, in id order.
func (c *Conn) Delegations(where string, args ...any) ([]*Delegation, error) {
	return collect(c, scanDelegation, "SELECT id, agent_id, principal_id, scopes, created_at, expires_at FROM agent_delegations "+where+" ORDER BY id", args...)
}

// ---------------------------------------------------------------- access requests

// AccessRequest is a just-in-time access request.
type AccessRequest struct {
	ID            int64
	IdentityID    int64
	AccountID     int64
	GroupID       int64
	Justification string
	DurationHours float64
	Status        string // pending | approved | denied | expired | revoked
	RequestedAt   time.Time
	DecidedAt     *time.Time
	DecidedBy     *string
	ExpiresAt     *time.Time
	EdgeID        *int64
}

const requestCols = `id, identity_id, account_id, group_id, justification, duration_hours, status, requested_at,
	decided_at, decided_by, expires_at, edge_id`

func scanRequest(s scanner) (*AccessRequest, error) {
	var r AccessRequest
	var req, dec, exp nullTime
	var by sql.NullString
	var edge sql.NullInt64
	if err := s.Scan(&r.ID, &r.IdentityID, &r.AccountID, &r.GroupID, &r.Justification, &r.DurationHours, &r.Status,
		&req, &dec, &by, &exp, &edge); err != nil {
		return nil, err
	}
	r.DecidedBy, r.EdgeID = strp(by), intp(edge)
	var err error
	if r.RequestedAt, err = req.val(); err != nil {
		return nil, err
	}
	if r.DecidedAt, err = dec.ptr(); err != nil {
		return nil, err
	}
	r.ExpiresAt, err = exp.ptr()
	return &r, err
}

// Requests returns access requests with a WHERE/ORDER BY tail.
func (c *Conn) Requests(tail string, args ...any) ([]*AccessRequest, error) {
	return collect(c, scanRequest, "SELECT "+requestCols+" FROM access_requests "+tail, args...)
}

// Request returns one access request by id.
func (c *Conn) Request(id int64) (*AccessRequest, error) {
	return one(c, scanRequest, "SELECT "+requestCols+" FROM access_requests WHERE id = ?", id)
}

// SaveRequest writes the mutable fields of an access request.
func (c *Conn) SaveRequest(r *AccessRequest) error {
	_, err := c.Exec(`UPDATE access_requests SET status = ?, decided_at = ?, decided_by = ?, expires_at = ?, edge_id = ?
		WHERE id = ?`, r.Status, TP(r.DecidedAt), SP(r.DecidedBy), TP(r.ExpiresAt), IP(r.EdgeID), r.ID)
	return err
}

// ---------------------------------------------------------------- reviews

// ReviewCampaign is an exception-only access review campaign.
type ReviewCampaign struct {
	ID            int64
	Name          string
	CreatedAt     time.Time
	Status        string
	UnusedDays    int
	TotalGrants   int
	AutoCertified int
}

func scanCampaign(s scanner) (*ReviewCampaign, error) {
	var x ReviewCampaign
	var created nullTime
	if err := s.Scan(&x.ID, &x.Name, &created, &x.Status, &x.UnusedDays, &x.TotalGrants, &x.AutoCertified); err != nil {
		return nil, err
	}
	var err error
	x.CreatedAt, err = created.val()
	return &x, err
}

const campaignCols = `id, name, created_at, status, unused_days, total_grants, auto_certified`

// Campaigns returns campaigns with a WHERE/ORDER BY tail.
func (c *Conn) Campaigns(tail string, args ...any) ([]*ReviewCampaign, error) {
	return collect(c, scanCampaign, "SELECT "+campaignCols+" FROM review_campaigns "+tail, args...)
}

// Campaign returns one campaign by id.
func (c *Conn) Campaign(id int64) (*ReviewCampaign, error) {
	return one(c, scanCampaign, "SELECT "+campaignCols+" FROM review_campaigns WHERE id = ?", id)
}

// ReviewItem is one grant to be reviewed.
type ReviewItem struct {
	ID         int64
	CampaignID int64
	IdentityID int64
	EdgeID     *int64
	EdgeSrc    string
	EdgeDst    string
	GrantLabel string
	Reasons    []string
	Context    json.RawMessage
	ReviewerID *int64
	Decision   *string
	Comment    *string
	DecidedAt  *time.Time
}

const itemCols = `id, campaign_id, identity_id, edge_id, edge_src, edge_dst, grant_label, reasons, context,
	reviewer_id, decision, comment, decided_at`

func scanItem(s scanner) (*ReviewItem, error) {
	var x ReviewItem
	var edge, rev sql.NullInt64
	var reasons, ctx string
	var dec, com sql.NullString
	var at nullTime
	if err := s.Scan(&x.ID, &x.CampaignID, &x.IdentityID, &edge, &x.EdgeSrc, &x.EdgeDst, &x.GrantLabel, &reasons, &ctx,
		&rev, &dec, &com, &at); err != nil {
		return nil, err
	}
	x.EdgeID, x.ReviewerID, x.Decision, x.Comment = intp(edge), intp(rev), strp(dec), strp(com)
	if err := json.Unmarshal([]byte(reasons), &x.Reasons); err != nil {
		return nil, err
	}
	if x.Reasons == nil {
		x.Reasons = []string{}
	}
	x.Context = json.RawMessage(ctx)
	var err error
	x.DecidedAt, err = at.ptr()
	return &x, err
}

// CampaignItems returns a campaign's items in id order.
func (c *Conn) CampaignItems(campaignID int64) ([]*ReviewItem, error) {
	return collect(c, scanItem, "SELECT "+itemCols+" FROM review_items WHERE campaign_id = ? ORDER BY id", campaignID)
}

// Item returns one review item by id.
func (c *Conn) Item(id int64) (*ReviewItem, error) {
	return one(c, scanItem, "SELECT "+itemCols+" FROM review_items WHERE id = ?", id)
}

// ---------------------------------------------------------------- HRIS

// HrisEvent is a joiner/mover/leaver event from the HR feed.
type HrisEvent struct {
	ID          int64
	ExternalID  string
	Type        string
	IdentityID  *int64
	Payload     ojson.Object
	EffectiveAt time.Time
	Status      string // pending | executed
	ExecutedAt  *time.Time
}

const hrisCols = `id, external_id, type, identity_id, payload, effective_at, status, executed_at`

func scanHris(s scanner) (*HrisEvent, error) {
	var x HrisEvent
	var iid sql.NullInt64
	var payload string
	var eff, exe nullTime
	if err := s.Scan(&x.ID, &x.ExternalID, &x.Type, &iid, &payload, &eff, &x.Status, &exe); err != nil {
		return nil, err
	}
	x.IdentityID = intp(iid)
	v, err := ojson.Decode([]byte(payload))
	if err != nil {
		return nil, fmt.Errorf("store: hris event %d payload: %w", x.ID, err)
	}
	obj, ok := v.(ojson.Object)
	if !ok {
		return nil, fmt.Errorf("store: hris event %d payload is not an object", x.ID)
	}
	x.Payload = obj
	if x.EffectiveAt, err = eff.val(); err != nil {
		return nil, err
	}
	x.ExecutedAt, err = exe.ptr()
	return &x, err
}

// HrisEvents returns events with a WHERE/ORDER BY tail.
func (c *Conn) HrisEvents(tail string, args ...any) ([]*HrisEvent, error) {
	return collect(c, scanHris, "SELECT "+hrisCols+" FROM hris_events "+tail, args...)
}

// HrisEvent returns one event by id.
func (c *Conn) HrisEvent(id int64) (*HrisEvent, error) {
	return one(c, scanHris, "SELECT "+hrisCols+" FROM hris_events WHERE id = ?", id)
}

// ---------------------------------------------------------------- audit

// AuditEntry is one audit log row.
type AuditEntry struct {
	ID     int64
	At     time.Time
	Actor  string
	Action string
	Detail json.RawMessage
}

// Audit appends an audit log entry; detail is an ordered object.
func (c *Conn) Audit(now time.Time, actor, action string, detail ojson.Object) error {
	if detail == nil {
		detail = ojson.Object{}
	}
	d, err := JSON(detail)
	if err != nil {
		return err
	}
	_, err = c.Exec("INSERT INTO audit_log (at, actor, action, detail) VALUES (?, ?, ?, ?)", T(now), actor, action, d)
	return err
}

// AuditLog returns the newest entries first.
func (c *Conn) AuditLog(limit int) ([]*AuditEntry, error) {
	return collect(c, func(s scanner) (*AuditEntry, error) {
		var e AuditEntry
		var at nullTime
		var detail string
		if err := s.Scan(&e.ID, &at, &e.Actor, &e.Action, &detail); err != nil {
			return nil, err
		}
		e.Detail = json.RawMessage(detail)
		var err error
		e.At, err = at.val()
		return &e, err
	}, "SELECT id, at, actor, action, detail FROM audit_log ORDER BY id DESC LIMIT ?", limit)
}
