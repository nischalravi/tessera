package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ---------------------------------------------------------------- access requests

// AccessRequest is a just-in-time access request.
type AccessRequest struct {
	ID            int64
	TenantID      tenancy.ID
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
	// The platform users who requested and decided (nil for seed data and
	// system jobs). DecidedBy stays as the display string the UI shows.
	RequestedByUserID *uuid.UUID
	DecidedByUserID   *uuid.UUID
}

const requestCols = `r.id, r.tenant_id, r.identity_id, r.account_id, r.group_id, r.justification, r.duration_hours,
	r.status, r.requested_at, r.decided_at, r.decided_by, r.expires_at, r.edge_id, r.requested_by_user_id,
	r.decided_by_user_id`

var (
	requestsRecent = tq("access_requests.list_recent", `
		SELECT `+requestCols+` FROM access_requests r WHERE r.tenant_id = @tenant ORDER BY r.requested_at DESC, r.id`)
	requestsGet = tq("access_requests.get", `
		SELECT `+requestCols+` FROM access_requests r WHERE r.tenant_id = @tenant AND r.id = @id`)
	requestsExpired = tq("access_requests.expired_approved", `
		SELECT `+requestCols+` FROM access_requests r
		WHERE r.tenant_id = @tenant AND r.status = 'approved' AND r.expires_at <= @now ORDER BY r.id`)
	requestsOpenFor = tq("access_requests.open_for_identity", `
		SELECT `+requestCols+` FROM access_requests r
		WHERE r.tenant_id = @tenant AND r.identity_id = @identity_id AND r.status IN ('pending', 'approved') ORDER BY r.id`)
	requestsInsert = tq("access_requests.insert", `
		INSERT INTO access_requests (tenant_id, identity_id, account_id, group_id, justification, duration_hours, status,
			requested_at, decided_at, decided_by, expires_at, edge_id, requested_by_user_id, decided_by_user_id)
		VALUES (@tenant, @identity_id, @account_id, @group_id, @justification, @duration_hours, @status,
			@requested_at, @decided_at, @decided_by, @expires_at, @edge_id, @requested_by_user_id, @decided_by_user_id)`)
	requestsSave = tq("access_requests.save", `
		UPDATE access_requests SET status = @status, decided_at = @decided_at, decided_by = @decided_by,
			expires_at = @expires_at, edge_id = @edge_id, decided_by_user_id = @decided_by_user_id
		WHERE tenant_id = @tenant AND id = @id`)
	requestsCancel = tq("access_requests.cancel", `
		UPDATE access_requests SET status = CASE WHEN status = 'approved' THEN 'revoked' ELSE 'denied' END,
			decided_at = @at
		WHERE tenant_id = @tenant AND id = @id`)
	requestsCount = tq("access_requests.count", `
		SELECT count(*) FROM access_requests r WHERE r.tenant_id = @tenant`)
	requestsCountStatus = tq("access_requests.count_status", `
		SELECT count(r.id) FROM access_requests r WHERE r.tenant_id = @tenant AND r.status = @status`)
	// jitNeedsSweep backs jit.NeedsSweep: both subqueries are tenant-scoped.
	jitNeedsSweep = tq("jit.needs_sweep", `
		SELECT (SELECT count(*) FROM access_requests r
				WHERE r.tenant_id = @tenant AND r.status = 'approved' AND r.expires_at <= @now)
			+ (SELECT count(*) FROM grant_edges e WHERE e.tenant_id = @tenant AND e.source = 'jit' AND e.expires_at <= @now)`)
)

func scanRequest(s scanner) (*AccessRequest, error) {
	var r AccessRequest
	var tid string
	var req, dec, exp nullTime
	var by, reqBy, decBy sql.NullString
	var edge sql.NullInt64
	if err := s.Scan(&r.ID, &tid, &r.IdentityID, &r.AccountID, &r.GroupID, &r.Justification, &r.DurationHours, &r.Status,
		&req, &dec, &by, &exp, &edge, &reqBy, &decBy); err != nil {
		return nil, err
	}
	var err error
	if r.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if r.RequestedByUserID, err = uuidp(reqBy); err != nil {
		return nil, err
	}
	if r.DecidedByUserID, err = uuidp(decBy); err != nil {
		return nil, err
	}
	r.DecidedBy, r.EdgeID = strp(by), intp(edge)
	if r.RequestedAt, err = req.val(); err != nil {
		return nil, err
	}
	if r.DecidedAt, err = dec.ptr(); err != nil {
		return nil, err
	}
	r.ExpiresAt, err = exp.ptr()
	return &r, err
}

// RequestsByRecency returns access requests, most recently requested first.
func (tx *TenantTx) RequestsByRecency() ([]*AccessRequest, error) {
	return collect(tx, scanRequest, requestsRecent)
}

// Request returns one access request by id.
func (tx *TenantTx) Request(id int64) (*AccessRequest, error) {
	return one(tx, scanRequest, requestsGet, sql.Named("id", id))
}

// ExpiredApprovedRequests returns approved requests whose expiry is at or before now, in id order.
func (tx *TenantTx) ExpiredApprovedRequests(now time.Time) ([]*AccessRequest, error) {
	return collect(tx, scanRequest, requestsExpired, sql.Named("now", T(now)))
}

// OpenRequestsFor returns an identity's pending and approved requests, in id order.
func (tx *TenantTx) OpenRequestsFor(identityID int64) ([]*AccessRequest, error) {
	return collect(tx, scanRequest, requestsOpenFor, sql.Named("identity_id", identityID))
}

// InsertRequest inserts an access request and returns its id.
func (tx *TenantTx) InsertRequest(r *AccessRequest) (int64, error) {
	if err := tx.own(r.TenantID); err != nil {
		return 0, err
	}
	return tx.insert(requestsInsert, sql.Named("identity_id", r.IdentityID), sql.Named("account_id", r.AccountID),
		sql.Named("group_id", r.GroupID), sql.Named("justification", r.Justification),
		sql.Named("duration_hours", r.DurationHours), sql.Named("status", r.Status),
		sql.Named("requested_at", T(r.RequestedAt)), sql.Named("decided_at", TP(r.DecidedAt)),
		sql.Named("decided_by", SP(r.DecidedBy)), sql.Named("expires_at", TP(r.ExpiresAt)), sql.Named("edge_id", IP(r.EdgeID)),
		sql.Named("requested_by_user_id", uuidOrNil(r.RequestedByUserID)),
		sql.Named("decided_by_user_id", uuidOrNil(r.DecidedByUserID)))
}

// SaveRequest writes the mutable fields of an access request.
func (tx *TenantTx) SaveRequest(r *AccessRequest) error {
	_, err := tx.exec(requestsSave, sql.Named("status", r.Status), sql.Named("decided_at", TP(r.DecidedAt)),
		sql.Named("decided_by", SP(r.DecidedBy)), sql.Named("expires_at", TP(r.ExpiresAt)), sql.Named("edge_id", IP(r.EdgeID)),
		sql.Named("decided_by_user_id", uuidOrNil(r.DecidedByUserID)), sql.Named("id", r.ID))
	return err
}

// CancelRequest revokes an approved request or denies a pending one (JML leaver).
func (tx *TenantTx) CancelRequest(id int64, at time.Time) error {
	_, err := tx.exec(requestsCancel, sql.Named("at", T(at)), sql.Named("id", id))
	return err
}

// CountRequests counts access requests.
func (tx *TenantTx) CountRequests() (int, error) { return tx.count(requestsCount) }

// CountRequestsByStatus counts access requests with a status.
func (tx *TenantTx) CountRequestsByStatus(status string) (int, error) {
	return tx.count(requestsCountStatus, sql.Named("status", status))
}

// JITSweepPending counts approved requests and JIT edges whose expiry is at or before now.
func (tx *TenantTx) JITSweepPending(now time.Time) (int, error) {
	return tx.count(jitNeedsSweep, sql.Named("now", T(now)))
}

// ---------------------------------------------------------------- reviews

// ReviewCampaign is an exception-only access review campaign.
type ReviewCampaign struct {
	ID            int64
	TenantID      tenancy.ID
	Name          string
	CreatedAt     time.Time
	Status        string
	UnusedDays    int
	TotalGrants   int
	AutoCertified int
}

const campaignCols = `c.id, c.tenant_id, c.name, c.created_at, c.status, c.unused_days, c.total_grants, c.auto_certified`

var (
	campaignsNewest = tq("review_campaigns.list_newest", `
		SELECT `+campaignCols+` FROM review_campaigns c WHERE c.tenant_id = @tenant ORDER BY c.id DESC`)
	campaignsGet = tq("review_campaigns.get", `
		SELECT `+campaignCols+` FROM review_campaigns c WHERE c.tenant_id = @tenant AND c.id = @id`)
	campaignsInsert = tq("review_campaigns.insert", `
		INSERT INTO review_campaigns (tenant_id, name, created_at, status, unused_days, total_grants, auto_certified)
		VALUES (@tenant, @name, @created_at, @status, @unused_days, @total_grants, @auto_certified)`)
	campaignsSetTotals = tq("review_campaigns.set_totals", `
		UPDATE review_campaigns SET total_grants = @total_grants, auto_certified = @auto_certified
		WHERE tenant_id = @tenant AND id = @id`)
	campaignsComplete = tq("review_campaigns.complete", `
		UPDATE review_campaigns SET status = 'completed' WHERE tenant_id = @tenant AND id = @id`)
)

func scanCampaign(s scanner) (*ReviewCampaign, error) {
	var x ReviewCampaign
	var tid string
	var created nullTime
	if err := s.Scan(&x.ID, &tid, &x.Name, &created, &x.Status, &x.UnusedDays, &x.TotalGrants, &x.AutoCertified); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	x.CreatedAt, err = created.val()
	return &x, err
}

// CampaignsNewestFirst returns campaigns, newest (highest id) first.
func (tx *TenantTx) CampaignsNewestFirst() ([]*ReviewCampaign, error) {
	return collect(tx, scanCampaign, campaignsNewest)
}

// Campaign returns one campaign by id.
func (tx *TenantTx) Campaign(id int64) (*ReviewCampaign, error) {
	return one(tx, scanCampaign, campaignsGet, sql.Named("id", id))
}

// InsertCampaign inserts a campaign and returns its id.
func (tx *TenantTx) InsertCampaign(c *ReviewCampaign) (int64, error) {
	if err := tx.own(c.TenantID); err != nil {
		return 0, err
	}
	return tx.insert(campaignsInsert, sql.Named("name", c.Name), sql.Named("created_at", T(c.CreatedAt)),
		sql.Named("status", c.Status), sql.Named("unused_days", c.UnusedDays), sql.Named("total_grants", c.TotalGrants),
		sql.Named("auto_certified", c.AutoCertified))
}

// SetCampaignTotals records how many grants a campaign covered and auto-certified.
func (tx *TenantTx) SetCampaignTotals(id int64, total, autoCertified int) error {
	_, err := tx.exec(campaignsSetTotals, sql.Named("total_grants", total), sql.Named("auto_certified", autoCertified),
		sql.Named("id", id))
	return err
}

// CompleteCampaign marks a campaign completed.
func (tx *TenantTx) CompleteCampaign(id int64) error {
	_, err := tx.exec(campaignsComplete, sql.Named("id", id))
	return err
}

// ReviewItem is one grant to be reviewed.
type ReviewItem struct {
	ID         int64
	TenantID   tenancy.ID
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
	// DecidedByUserID is the platform user who decided (nil before PR5 data).
	DecidedByUserID *uuid.UUID
}

const itemCols = `ri.id, ri.tenant_id, ri.campaign_id, ri.identity_id, ri.edge_id, ri.edge_src, ri.edge_dst, ri.grant_label,
	ri.reasons, ri.context, ri.reviewer_id, ri.decision, ri.comment, ri.decided_at, ri.decided_by_user_id`

var (
	itemsByCampaign = tq("review_items.by_campaign", `
		SELECT `+itemCols+` FROM review_items ri WHERE ri.tenant_id = @tenant AND ri.campaign_id = @campaign_id ORDER BY ri.id`)
	itemsGet = tq("review_items.get", `
		SELECT `+itemCols+` FROM review_items ri WHERE ri.tenant_id = @tenant AND ri.id = @id`)
	itemsInsert = tq("review_items.insert", `
		INSERT INTO review_items (tenant_id, campaign_id, identity_id, edge_id, edge_src, edge_dst, grant_label, reasons,
			context, reviewer_id)
		VALUES (@tenant, @campaign_id, @identity_id, @edge_id, @edge_src, @edge_dst, @grant_label, @reasons,
			@context, @reviewer_id)`)
	itemsDecide = tq("review_items.decide", `
		UPDATE review_items SET decision = @decision, comment = @comment, decided_at = @decided_at,
			decided_by_user_id = @decided_by_user_id
		WHERE tenant_id = @tenant AND id = @id AND (decision IS NULL OR decision = '')`)
	itemsCountOpenInCampaign = tq("review_items.count_open_in_campaign", `
		SELECT count(*) FROM review_items ri
		WHERE ri.tenant_id = @tenant AND ri.campaign_id = @campaign_id AND (ri.decision IS NULL OR ri.decision = '')`)
	itemsCountUndecided = tq("review_items.count_undecided", `
		SELECT count(ri.id) FROM review_items ri WHERE ri.tenant_id = @tenant AND ri.decision IS NULL`)
)

func scanItem(s scanner) (*ReviewItem, error) {
	var x ReviewItem
	var tid string
	var edge, rev sql.NullInt64
	var reasons, ctx string
	var dec, com, by sql.NullString
	var at nullTime
	if err := s.Scan(&x.ID, &tid, &x.CampaignID, &x.IdentityID, &edge, &x.EdgeSrc, &x.EdgeDst, &x.GrantLabel, &reasons, &ctx,
		&rev, &dec, &com, &at, &by); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if x.DecidedByUserID, err = uuidp(by); err != nil {
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
	x.DecidedAt, err = at.ptr()
	return &x, err
}

// CampaignItems returns a campaign's items in id order.
func (tx *TenantTx) CampaignItems(campaignID int64) ([]*ReviewItem, error) {
	return collect(tx, scanItem, itemsByCampaign, sql.Named("campaign_id", campaignID))
}

// Item returns one review item by id.
func (tx *TenantTx) Item(id int64) (*ReviewItem, error) {
	return one(tx, scanItem, itemsGet, sql.Named("id", id))
}

// InsertReviewItem inserts an undecided review item. Context must already be
// encoded JSON.
func (tx *TenantTx) InsertReviewItem(x *ReviewItem) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	reasons, err := JSON(x.Reasons)
	if err != nil {
		return err
	}
	_, err = tx.exec(itemsInsert, sql.Named("campaign_id", x.CampaignID), sql.Named("identity_id", x.IdentityID),
		sql.Named("edge_id", IP(x.EdgeID)), sql.Named("edge_src", x.EdgeSrc), sql.Named("edge_dst", x.EdgeDst),
		sql.Named("grant_label", x.GrantLabel), sql.Named("reasons", reasons), sql.Named("context", string(x.Context)),
		sql.Named("reviewer_id", IP(x.ReviewerID)))
	return err
}

// DecideItem records a decision on a review item, made by the platform user by.
// The update is conditional on the item being undecided (NULL or empty), so
// a decision is written once even under concurrent requests; applied is false
// when the item was already decided (or does not exist in this tenant).
func (tx *TenantTx) DecideItem(id int64, decision string, comment *string, at time.Time, by UserRef) (applied bool, err error) {
	res, err := tx.exec(itemsDecide, sql.Named("decision", decision), sql.Named("comment", SP(comment)),
		sql.Named("decided_at", T(at)), sql.Named("decided_by_user_id", by.idOrNil()), sql.Named("id", id))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// CountOpenItems counts a campaign's undecided items (NULL or empty decision).
func (tx *TenantTx) CountOpenItems(campaignID int64) (int, error) {
	return tx.count(itemsCountOpenInCampaign, sql.Named("campaign_id", campaignID))
}

// CountUndecidedItems counts review items with a NULL decision, across campaigns.
func (tx *TenantTx) CountUndecidedItems() (int, error) { return tx.count(itemsCountUndecided) }

// ---------------------------------------------------------------- HRIS

// HrisEvent is a joiner/mover/leaver event from the HR feed.
type HrisEvent struct {
	ID          int64
	TenantID    tenancy.ID
	ExternalID  string
	Type        string
	IdentityID  *int64
	Payload     ojson.Object
	EffectiveAt time.Time
	Status      string // pending | executed
	ExecutedAt  *time.Time
	// ExecutedByUserID is the platform user who executed the event.
	ExecutedByUserID *uuid.UUID
}

const hrisCols = `h.id, h.tenant_id, h.external_id, h.type, h.identity_id, h.payload, h.effective_at, h.status, h.executed_at,
	h.executed_by_user_id`

var (
	hrisList = tq("hris_events.list", `
		SELECT `+hrisCols+` FROM hris_events h WHERE h.tenant_id = @tenant ORDER BY h.id`)
	hrisForUI = tq("hris_events.list_for_ui", `
		SELECT `+hrisCols+` FROM hris_events h WHERE h.tenant_id = @tenant
		ORDER BY h.status DESC, h.effective_at DESC, h.id`)
	hrisGet = tq("hris_events.get", `
		SELECT `+hrisCols+` FROM hris_events h WHERE h.tenant_id = @tenant AND h.id = @id`)
	hrisUpsert = tq("hris_events.upsert", `
		INSERT INTO hris_events (tenant_id, external_id, type, identity_id, payload, effective_at, status)
		VALUES (@tenant, @external_id, @type, @identity_id, @payload, @effective_at, @status)
		ON CONFLICT (tenant_id, external_id) DO UPDATE SET type = excluded.type, identity_id = excluded.identity_id,
			payload = excluded.payload, effective_at = excluded.effective_at,
			status = CASE WHEN hris_events.status = 'executed' THEN hris_events.status ELSE excluded.status END`)
	hrisInsert = tq("hris_events.insert", `
		INSERT INTO hris_events (tenant_id, external_id, type, identity_id, payload, effective_at, status, executed_at)
		VALUES (@tenant, @external_id, @type, @identity_id, @payload, @effective_at, @status, @executed_at)`)
	hrisSetIdentity = tq("hris_events.set_identity", `
		UPDATE hris_events SET identity_id = @identity_id WHERE tenant_id = @tenant AND id = @id`)
	hrisMarkExecuted = tq("hris_events.mark_executed", `
		UPDATE hris_events SET status = 'executed', executed_at = @at, executed_by_user_id = @executed_by_user_id
		WHERE tenant_id = @tenant AND id = @id`)
	hrisCount = tq("hris_events.count", `
		SELECT count(h.id) FROM hris_events h WHERE h.tenant_id = @tenant`)
	hrisCountStatus = tq("hris_events.count_status", `
		SELECT count(h.id) FROM hris_events h WHERE h.tenant_id = @tenant AND h.status = @status`)
)

func scanHris(s scanner) (*HrisEvent, error) {
	var x HrisEvent
	var tid string
	var iid sql.NullInt64
	var payload string
	var eff, exe nullTime
	var by sql.NullString
	if err := s.Scan(&x.ID, &tid, &x.ExternalID, &x.Type, &iid, &payload, &eff, &x.Status, &exe, &by); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if x.ExecutedByUserID, err = uuidp(by); err != nil {
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

// HrisEvents returns every HRIS event, in id order.
func (tx *TenantTx) HrisEvents() ([]*HrisEvent, error) { return collect(tx, scanHris, hrisList) }

// HrisEventsForUI returns HRIS events pending first, newest effective date first.
func (tx *TenantTx) HrisEventsForUI() ([]*HrisEvent, error) { return collect(tx, scanHris, hrisForUI) }

// HrisEvent returns one event by id.
func (tx *TenantTx) HrisEvent(id int64) (*HrisEvent, error) {
	return one(tx, scanHris, hrisGet, sql.Named("id", id))
}

func payloadJSON(p ojson.Object) (string, error) {
	if p == nil {
		p = ojson.Object{}
	}
	return JSON(p)
}

// UpsertHrisEvent inserts an event or updates the one with the same external id.
func (tx *TenantTx) UpsertHrisEvent(e *HrisEvent) error {
	if err := tx.own(e.TenantID); err != nil {
		return err
	}
	p, err := payloadJSON(e.Payload)
	if err != nil {
		return err
	}
	_, err = tx.exec(hrisUpsert, sql.Named("external_id", e.ExternalID), sql.Named("type", e.Type),
		sql.Named("identity_id", IP(e.IdentityID)), sql.Named("payload", p), sql.Named("effective_at", T(e.EffectiveAt)),
		sql.Named("status", e.Status))
	return err
}

// InsertHrisEvent inserts an event and returns its id.
func (tx *TenantTx) InsertHrisEvent(e *HrisEvent) (int64, error) {
	if err := tx.own(e.TenantID); err != nil {
		return 0, err
	}
	p, err := payloadJSON(e.Payload)
	if err != nil {
		return 0, err
	}
	return tx.insert(hrisInsert, sql.Named("external_id", e.ExternalID), sql.Named("type", e.Type),
		sql.Named("identity_id", IP(e.IdentityID)), sql.Named("payload", p), sql.Named("effective_at", T(e.EffectiveAt)),
		sql.Named("status", e.Status), sql.Named("executed_at", TP(e.ExecutedAt)))
}

// SetHrisEventIdentity links an event to an identity.
func (tx *TenantTx) SetHrisEventIdentity(id, identityID int64) error {
	_, err := tx.exec(hrisSetIdentity, sql.Named("identity_id", identityID), sql.Named("id", id))
	return err
}

// MarkHrisEventExecuted marks an event executed at, by the platform user by.
func (tx *TenantTx) MarkHrisEventExecuted(id int64, at time.Time, by UserRef) error {
	_, err := tx.exec(hrisMarkExecuted, sql.Named("at", T(at)), sql.Named("executed_by_user_id", by.idOrNil()),
		sql.Named("id", id))
	return err
}

// CountHrisEvents counts HRIS events.
func (tx *TenantTx) CountHrisEvents() (int, error) { return tx.count(hrisCount) }

// CountHrisEventsByStatus counts HRIS events with a status.
func (tx *TenantTx) CountHrisEventsByStatus(status string) (int, error) {
	return tx.count(hrisCountStatus, sql.Named("status", status))
}

// uuidp parses an optional UUID column.
func uuidp(n sql.NullString) (*uuid.UUID, error) {
	if !n.Valid {
		return nil, nil
	}
	u, err := uuid.Parse(n.String)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
