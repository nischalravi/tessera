package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// The access request service (schema/0205_requests.sql, issue #164).

// CatalogItem is the request metadata of one group.
type CatalogItem struct {
	ID                  string
	GroupID             int64
	Requestable         bool
	Description         string
	OwnerIdentityID     *int64
	Risk                string // low, medium, high
	EligibleTypes       []string
	EligibleDepartments []string
	DefaultHours        *float64 // nil: until removed
	MaxHours            *float64 // nil: no limit
	UpdatedBy           *string
	UpdatedAt           time.Time
}

// RequestLine is one beneficiary's request for one catalog item.
type RequestLine struct {
	ID             string
	BatchID        string
	CatalogItemID  string
	GroupID        int64
	BeneficiaryID  int64
	AccountID      int64
	RequestedBy    string
	Justification  string
	DurationHours  *float64
	Status         string
	RequestedAt    time.Time
	DecidedBy      *string
	DecidedAt      *time.Time
	DecisionReason *string
	EdgeID         *int64
	ExpiresAt      *time.Time
	ClosedAt       *time.Time
}

// Request line statuses.
const (
	RequestPending   = "pending"
	RequestApproved  = "approved"
	RequestDenied    = "denied"
	RequestCancelled = "cancelled"
	RequestExpired   = "expired"
	RequestRemoved   = "removed"
)

// RequestEvent is one entry of a line's history.
type RequestEvent struct {
	ID          int64
	LineID      string
	Event       string
	ActorUserID *string
	Actor       string
	Note        *string
	At          time.Time
}

// RequestFilter selects request lines; zero fields match everything.
type RequestFilter struct {
	Status      string
	RequestedBy string // platform user id
	Beneficiary int64
	// Involving matches lines requested by this user or for this identity.
	InvolvingUser     string
	InvolvingIdentity int64
	Limit             int
}

const catalogCols = `c.id, c.group_id, c.requestable, c.description, c.owner_identity_id, c.risk, c.eligible_types,
	c.eligible_departments, c.default_hours, c.max_hours, c.updated_by, c.updated_at`

const lineCols = `l.id, l.batch_id, l.catalog_item_id, l.group_id, l.beneficiary_id, l.account_id, l.requested_by,
	l.justification, l.duration_hours, l.status, l.requested_at, l.decided_by, l.decided_at, l.decision_reason,
	l.edge_id, l.expires_at, l.closed_at`

var (
	catalogList = tq("catalog_items.list", `
		SELECT `+catalogCols+` FROM catalog_items c WHERE c.tenant_id = @tenant ORDER BY c.group_id`)
	catalogGet = tq("catalog_items.get", `
		SELECT `+catalogCols+` FROM catalog_items c WHERE c.tenant_id = @tenant AND c.id = @id`)
	catalogByGroup = tq("catalog_items.by_group", `
		SELECT `+catalogCols+` FROM catalog_items c WHERE c.tenant_id = @tenant AND c.group_id = @group_id`)
	catalogPut = tq("catalog_items.put", `
		INSERT INTO catalog_items (id, tenant_id, group_id, requestable, description, owner_identity_id, risk,
			eligible_types, eligible_departments, default_hours, max_hours, updated_by, updated_at)
		VALUES (@id, @tenant, @group_id, @requestable, @description, @owner_identity_id, @risk, @eligible_types,
			@eligible_departments, @default_hours, @max_hours, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, group_id) DO UPDATE SET requestable = excluded.requestable,
			description = excluded.description, owner_identity_id = excluded.owner_identity_id, risk = excluded.risk,
			eligible_types = excluded.eligible_types, eligible_departments = excluded.eligible_departments,
			default_hours = excluded.default_hours, max_hours = excluded.max_hours, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)

	linesFiltered = tq("access_request_lines.filtered", `
		SELECT `+lineCols+` FROM access_request_lines l WHERE l.tenant_id = @tenant
			AND (@status = '' OR l.status = @status)
			AND (@requested_by = '' OR l.requested_by = @requested_by)
			AND (@beneficiary = 0 OR l.beneficiary_id = @beneficiary)
			AND ((@inv_user = '' AND @inv_identity = 0) OR l.requested_by = @inv_user OR l.beneficiary_id = @inv_identity)
		ORDER BY l.requested_at DESC, l.id LIMIT @limit`)
	linesGet = tq("access_request_lines.get", `
		SELECT `+lineCols+` FROM access_request_lines l WHERE l.tenant_id = @tenant AND l.id = @id`)
	linesOpenFor = tq("access_request_lines.open_for", `
		SELECT `+lineCols+` FROM access_request_lines l WHERE l.tenant_id = @tenant AND l.beneficiary_id = @beneficiary
			AND l.group_id = @group_id AND l.status IN ('pending','approved')`)
	linesDue = tq("access_request_lines.due", `
		SELECT `+lineCols+` FROM access_request_lines l WHERE l.tenant_id = @tenant AND l.status = 'approved'
			AND ((l.expires_at IS NOT NULL AND l.expires_at <= @now)
				OR NOT EXISTS (SELECT 1 FROM grant_edges e WHERE e.tenant_id = @tenant AND e.id = l.edge_id))
		ORDER BY l.expires_at, l.id`)
	linesCountDue = tq("access_request_lines.count_due", `
		SELECT count(l.id) FROM access_request_lines l WHERE l.tenant_id = @tenant AND l.status = 'approved'
			AND ((l.expires_at IS NOT NULL AND l.expires_at <= @now)
				OR NOT EXISTS (SELECT 1 FROM grant_edges e WHERE e.tenant_id = @tenant AND e.id = l.edge_id))`)
	linesInsert = tq("access_request_lines.insert", `
		INSERT INTO access_request_lines (id, tenant_id, batch_id, catalog_item_id, group_id, beneficiary_id, account_id,
			requested_by, justification, duration_hours, status, requested_at)
		VALUES (@id, @tenant, @batch_id, @catalog_item_id, @group_id, @beneficiary_id, @account_id, @requested_by,
			@justification, @duration_hours, 'pending', @requested_at)`)
	linesSave = tq("access_request_lines.save", `
		UPDATE access_request_lines SET status = @status, decided_by = @decided_by, decided_at = @decided_at,
			decision_reason = @decision_reason, edge_id = @edge_id, expires_at = @expires_at, closed_at = @closed_at
		WHERE tenant_id = @tenant AND id = @id AND status = @from`)

	eventsInsert = tq("access_request_events.insert", `
		INSERT INTO access_request_events (tenant_id, line_id, event, actor_user_id, actor, note, at)
		VALUES (@tenant, @line_id, @event, @actor_user_id, @actor, @note, @at)`)
	eventsForLine = tq("access_request_events.for_line", `
		SELECT e.id, e.line_id, e.event, e.actor_user_id, e.actor, e.note, e.at FROM access_request_events e
		WHERE e.tenant_id = @tenant AND e.line_id = @line_id ORDER BY e.id`)

	edgesDeleteRequest = tq("grant_edges.delete_request", `
		DELETE FROM grant_edges WHERE tenant_id = @tenant AND id = @id AND source = 'request'`)
)

func parseStrList(s string) ([]string, error) {
	out := []string{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("store: JSON list: %w", err)
	}
	return out, nil
}

func floatp(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	v := n.Float64
	return &v
}

func fp(f *float64) any {
	if f == nil {
		return nil
	}
	return *f
}

func scanCatalogItem(s scanner) (*CatalogItem, error) {
	var c CatalogItem
	var req int
	var owner sql.NullInt64
	var types, depts string
	var def, max sql.NullFloat64
	var by sql.NullString
	var at nullTime
	if err := s.Scan(&c.ID, &c.GroupID, &req, &c.Description, &owner, &c.Risk, &types, &depts, &def, &max, &by, &at); err != nil {
		return nil, err
	}
	var err error
	c.Requestable, c.OwnerIdentityID, c.DefaultHours, c.MaxHours, c.UpdatedBy = req != 0, intp(owner), floatp(def), floatp(max), strp(by)
	if c.EligibleTypes, err = parseStrList(types); err != nil {
		return nil, err
	}
	if c.EligibleDepartments, err = parseStrList(depts); err != nil {
		return nil, err
	}
	c.UpdatedAt, err = at.val()
	return &c, err
}

func scanLine(s scanner) (*RequestLine, error) {
	var l RequestLine
	var dur sql.NullFloat64
	var at, decAt, exp, closed nullTime
	var decBy, reason sql.NullString
	var edge sql.NullInt64
	if err := s.Scan(&l.ID, &l.BatchID, &l.CatalogItemID, &l.GroupID, &l.BeneficiaryID, &l.AccountID, &l.RequestedBy,
		&l.Justification, &dur, &l.Status, &at, &decBy, &decAt, &reason, &edge, &exp, &closed); err != nil {
		return nil, err
	}
	var err error
	l.DurationHours, l.DecidedBy, l.DecisionReason, l.EdgeID = floatp(dur), strp(decBy), strp(reason), intp(edge)
	if l.RequestedAt, err = at.val(); err != nil {
		return nil, err
	}
	if l.DecidedAt, err = decAt.ptr(); err != nil {
		return nil, err
	}
	if l.ExpiresAt, err = exp.ptr(); err != nil {
		return nil, err
	}
	l.ClosedAt, err = closed.ptr()
	return &l, err
}

func scanRequestEvent(s scanner) (*RequestEvent, error) {
	var e RequestEvent
	var uid, note sql.NullString
	var at nullTime
	if err := s.Scan(&e.ID, &e.LineID, &e.Event, &uid, &e.Actor, &note, &at); err != nil {
		return nil, err
	}
	e.ActorUserID, e.Note = strp(uid), strp(note)
	var err error
	e.At, err = at.val()
	return &e, err
}

// CatalogItems returns every catalog item, by group id.
func (tx *TenantTx) CatalogItems() ([]*CatalogItem, error) { return collect(tx, scanCatalogItem, catalogList) }

// CatalogItem returns one item, or ErrNotFound.
func (tx *TenantTx) CatalogItem(id string) (*CatalogItem, error) {
	return one(tx, scanCatalogItem, catalogGet, sql.Named("id", id))
}

// CatalogItemForGroup returns a group's item, or ErrNotFound.
func (tx *TenantTx) CatalogItemForGroup(groupID int64) (*CatalogItem, error) {
	return one(tx, scanCatalogItem, catalogByGroup, sql.Named("group_id", groupID))
}

// PutCatalogItem inserts or replaces a group's item (keyed by group; an
// existing item keeps its id).
func (tx *TenantTx) PutCatalogItem(c *CatalogItem) error {
	types, err := JSON(nonNil(c.EligibleTypes))
	if err != nil {
		return err
	}
	depts, err := JSON(nonNil(c.EligibleDepartments))
	if err != nil {
		return err
	}
	_, err = tx.exec(catalogPut, sql.Named("id", c.ID), sql.Named("group_id", c.GroupID),
		sql.Named("requestable", B(c.Requestable)), sql.Named("description", c.Description),
		sql.Named("owner_identity_id", IP(c.OwnerIdentityID)), sql.Named("risk", c.Risk),
		sql.Named("eligible_types", types), sql.Named("eligible_departments", depts),
		sql.Named("default_hours", fp(c.DefaultHours)), sql.Named("max_hours", fp(c.MaxHours)),
		sql.Named("updated_by", SP(c.UpdatedBy)), sql.Named("updated_at", T(c.UpdatedAt)))
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// RequestLines returns the lines matching f, newest first.
func (tx *TenantTx) RequestLines(f RequestFilter) ([]*RequestLine, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = -1
	}
	return collect(tx, scanLine, linesFiltered, sql.Named("status", f.Status), sql.Named("requested_by", f.RequestedBy),
		sql.Named("beneficiary", f.Beneficiary), sql.Named("inv_user", f.InvolvingUser),
		sql.Named("inv_identity", f.InvolvingIdentity), sql.Named("limit", limit))
}

// RequestLine returns one line, or ErrNotFound.
func (tx *TenantTx) RequestLine(id string) (*RequestLine, error) {
	return one(tx, scanLine, linesGet, sql.Named("id", id))
}

// OpenRequestLine returns the pending or approved line of a beneficiary for a
// group, or ErrNotFound.
func (tx *TenantTx) OpenRequestLine(beneficiary, groupID int64) (*RequestLine, error) {
	return one(tx, scanLine, linesOpenFor, sql.Named("beneficiary", beneficiary), sql.Named("group_id", groupID))
}

// DueRequestLines returns approved lines that expired by now or whose grant
// edge is gone (removed elsewhere, for example by an access review).
func (tx *TenantTx) DueRequestLines(now time.Time) ([]*RequestLine, error) {
	return collect(tx, scanLine, linesDue, sql.Named("now", T(now)))
}

// CountDueRequestLines counts DueRequestLines.
func (tx *TenantTx) CountDueRequestLines(now time.Time) (int, error) {
	return tx.count(linesCountDue, sql.Named("now", T(now)))
}

// InsertRequestLine files a pending line.
func (tx *TenantTx) InsertRequestLine(l *RequestLine) error {
	_, err := tx.exec(linesInsert, sql.Named("id", l.ID), sql.Named("batch_id", l.BatchID),
		sql.Named("catalog_item_id", l.CatalogItemID), sql.Named("group_id", l.GroupID),
		sql.Named("beneficiary_id", l.BeneficiaryID), sql.Named("account_id", l.AccountID),
		sql.Named("requested_by", l.RequestedBy), sql.Named("justification", l.Justification),
		sql.Named("duration_hours", fp(l.DurationHours)), sql.Named("requested_at", T(l.RequestedAt)))
	return err
}

// SaveRequestLine moves a line from status from to l's state; ErrNotFound
// if it is no longer in from (a concurrent decision).
func (tx *TenantTx) SaveRequestLine(l *RequestLine, from string) error {
	res, err := tx.exec(linesSave, sql.Named("id", l.ID), sql.Named("from", from), sql.Named("status", l.Status),
		sql.Named("decided_by", SP(l.DecidedBy)), sql.Named("decided_at", TP(l.DecidedAt)),
		sql.Named("decision_reason", SP(l.DecisionReason)), sql.Named("edge_id", IP(l.EdgeID)),
		sql.Named("expires_at", TP(l.ExpiresAt)), sql.Named("closed_at", TP(l.ClosedAt)))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddRequestEvent appends to a line's history.
func (tx *TenantTx) AddRequestEvent(e *RequestEvent) error {
	_, err := tx.exec(eventsInsert, sql.Named("line_id", e.LineID), sql.Named("event", e.Event),
		sql.Named("actor_user_id", SP(e.ActorUserID)), sql.Named("actor", e.Actor), sql.Named("note", SP(e.Note)),
		sql.Named("at", T(e.At)))
	return err
}

// RequestEvents returns a line's history, oldest first.
func (tx *TenantTx) RequestEvents(lineID string) ([]*RequestEvent, error) {
	return collect(tx, scanRequestEvent, eventsForLine, sql.Named("line_id", lineID))
}

// DeleteRequestEdge deletes a grant edge if it was granted by a request.
func (tx *TenantTx) DeleteRequestEdge(id int64) error {
	_, err := tx.exec(edgesDeleteRequest, sql.Named("id", id))
	return err
}
