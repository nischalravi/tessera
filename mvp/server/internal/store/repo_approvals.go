package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Approval routing (schema/0206_approvals.sql, issue #165).

// Stage kinds.
const (
	StageManager = "manager"
	StageOwner   = "owner"
	StageDecider = "decider"
)

// Stage statuses.
const (
	StageQueued   = "queued"
	StageWaiting  = "waiting"
	StageApproved = "approved"
	StageDenied   = "denied"
	StageClosed   = "closed"
)

// ApprovalPolicy is a catalog item's ordered approval stages.
type ApprovalPolicy struct {
	CatalogItemID      string
	Stages             []string
	EscalateAfterHours float64
	UpdatedBy          *string
	UpdatedAt          time.Time
}

// RequestStage is one approval stage of a request line.
type RequestStage struct {
	LineID     string
	Idx        int
	Kind       string
	AssigneeID *int64 // identity
	Status     string
	StartedAt  *time.Time
	DueAt      *time.Time
	DecidedBy  *string // platform user
	OnBehalfOf *string // the delegating user, when decided under a delegation
	DecidedAt  *time.Time
	Reason     *string
}

// ApprovalDelegationRow hands FromUser's approvals to ToUser between StartsAt and EndsAt.
type ApprovalDelegationRow struct {
	ID        string
	FromUser  string
	ToUser    string
	StartsAt  time.Time
	EndsAt    time.Time
	Reason    string
	CreatedAt time.Time
	RevokedAt *time.Time
	RevokedBy *string
}

const stageCols = `s.line_id, s.idx, s.kind, s.assignee_identity_id, s.status, s.started_at, s.due_at, s.decided_by,
	s.on_behalf_of, s.decided_at, s.reason`

const delegationCols = `d.id, d.from_user, d.to_user, d.starts_at, d.ends_at, d.reason, d.created_at, d.revoked_at, d.revoked_by`

var (
	policiesList = tq("approval_policies.list", `
		SELECT p.catalog_item_id, p.stages, p.escalate_after_hours, p.updated_by, p.updated_at FROM approval_policies p
		WHERE p.tenant_id = @tenant ORDER BY p.catalog_item_id`)
	policiesGet = tq("approval_policies.get", `
		SELECT p.catalog_item_id, p.stages, p.escalate_after_hours, p.updated_by, p.updated_at FROM approval_policies p
		WHERE p.tenant_id = @tenant AND p.catalog_item_id = @item`)
	policiesPut = tq("approval_policies.put", `
		INSERT INTO approval_policies (tenant_id, catalog_item_id, stages, escalate_after_hours, updated_by, updated_at)
		VALUES (@tenant, @item, @stages, @hours, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, catalog_item_id) DO UPDATE SET stages = excluded.stages,
			escalate_after_hours = excluded.escalate_after_hours, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)

	stagesInsert = tq("access_request_stages.insert", `
		INSERT INTO access_request_stages (tenant_id, line_id, idx, kind, assignee_identity_id, status, started_at, due_at)
		VALUES (@tenant, @line_id, @idx, @kind, @assignee, @status, @started_at, @due_at)`)
	stagesForLine = tq("access_request_stages.for_line", `
		SELECT `+stageCols+` FROM access_request_stages s WHERE s.tenant_id = @tenant AND s.line_id = @line_id ORDER BY s.idx`)
	stagesWaiting = tq("access_request_stages.waiting", `
		SELECT `+stageCols+` FROM access_request_stages s WHERE s.tenant_id = @tenant AND s.status = 'waiting'
		ORDER BY s.started_at, s.line_id`)
	stagesSave = tq("access_request_stages.save", `
		UPDATE access_request_stages SET status = @status, started_at = @started_at, due_at = @due_at,
			decided_by = @decided_by, on_behalf_of = @on_behalf_of, decided_at = @decided_at, reason = @reason
		WHERE tenant_id = @tenant AND line_id = @line_id AND idx = @idx AND status = @from`)
	stagesCloseOpen = tq("access_request_stages.close_open", `
		UPDATE access_request_stages SET status = 'closed' WHERE tenant_id = @tenant AND line_id = @line_id
			AND status IN ('queued','waiting')`)

	usersLinkedTo = tq("platform_users.ids_linked_to", `
		SELECT u.id FROM platform_users u WHERE u.tenant_id = @tenant AND u.identity_id = @identity_id
			AND u.status = 'active' ORDER BY u.id`)

	approvalDelegationsInsert = tq("approval_delegations.insert", `
		INSERT INTO approval_delegations (id, tenant_id, from_user, to_user, starts_at, ends_at, reason, created_at)
		VALUES (@id, @tenant, @from_user, @to_user, @starts_at, @ends_at, @reason, @created_at)`)
	approvalDelegationsInvolving = tq("approval_delegations.involving", `
		SELECT `+delegationCols+` FROM approval_delegations d WHERE d.tenant_id = @tenant
			AND (@user = '' OR d.from_user = @user OR d.to_user = @user) ORDER BY d.starts_at DESC, d.id`)
	approvalDelegationsGet = tq("approval_delegations.get", `
		SELECT `+delegationCols+` FROM approval_delegations d WHERE d.tenant_id = @tenant AND d.id = @id`)
	approvalDelegationsActiveTo = tq("approval_delegations.active_to", `
		SELECT `+delegationCols+` FROM approval_delegations d WHERE d.tenant_id = @tenant AND d.to_user = @user
			AND d.revoked_at IS NULL AND d.starts_at <= @now AND d.ends_at > @now ORDER BY d.id`)
	approvalDelegationsRevoke = tq("approval_delegations.revoke", `
		UPDATE approval_delegations SET revoked_at = @at, revoked_by = @by
		WHERE tenant_id = @tenant AND id = @id AND revoked_at IS NULL`)
)

func scanPolicy(s scanner) (*ApprovalPolicy, error) {
	var p ApprovalPolicy
	var stages string
	var by sql.NullString
	var at nullTime
	if err := s.Scan(&p.CatalogItemID, &stages, &p.EscalateAfterHours, &by, &at); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(stages), &p.Stages); err != nil {
		return nil, fmt.Errorf("store: approval_policies.stages: %w", err)
	}
	p.UpdatedBy = strp(by)
	var err error
	p.UpdatedAt, err = at.val()
	return &p, err
}

func scanStage(s scanner) (*RequestStage, error) {
	var st RequestStage
	var assignee sql.NullInt64
	var started, due, decAt nullTime
	var by, behalf, reason sql.NullString
	if err := s.Scan(&st.LineID, &st.Idx, &st.Kind, &assignee, &st.Status, &started, &due, &by, &behalf, &decAt, &reason); err != nil {
		return nil, err
	}
	st.AssigneeID, st.DecidedBy, st.OnBehalfOf, st.Reason = intp(assignee), strp(by), strp(behalf), strp(reason)
	var err error
	if st.StartedAt, err = started.ptr(); err != nil {
		return nil, err
	}
	if st.DueAt, err = due.ptr(); err != nil {
		return nil, err
	}
	st.DecidedAt, err = decAt.ptr()
	return &st, err
}

func scanApprovalDelegation(s scanner) (*ApprovalDelegationRow, error) {
	var d ApprovalDelegationRow
	var starts, ends, created, revoked nullTime
	var revBy sql.NullString
	if err := s.Scan(&d.ID, &d.FromUser, &d.ToUser, &starts, &ends, &d.Reason, &created, &revoked, &revBy); err != nil {
		return nil, err
	}
	var err error
	if d.StartsAt, err = starts.val(); err != nil {
		return nil, err
	}
	if d.EndsAt, err = ends.val(); err != nil {
		return nil, err
	}
	if d.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	d.RevokedBy = strp(revBy)
	d.RevokedAt, err = revoked.ptr()
	return &d, err
}

// ApprovalPolicies returns every item policy.
func (tx *TenantTx) ApprovalPolicies() ([]*ApprovalPolicy, error) {
	return collect(tx, scanPolicy, policiesList)
}

// ApprovalPolicy returns an item's policy, or ErrNotFound (one decider stage).
func (tx *TenantTx) ApprovalPolicy(itemID string) (*ApprovalPolicy, error) {
	return one(tx, scanPolicy, policiesGet, sql.Named("item", itemID))
}

// PutApprovalPolicy sets an item's policy.
func (tx *TenantTx) PutApprovalPolicy(p *ApprovalPolicy) error {
	stages, err := JSON(p.Stages)
	if err != nil {
		return err
	}
	_, err = tx.exec(policiesPut, sql.Named("item", p.CatalogItemID), sql.Named("stages", stages),
		sql.Named("hours", p.EscalateAfterHours), sql.Named("updated_by", SP(p.UpdatedBy)), sql.Named("updated_at", T(p.UpdatedAt)))
	return err
}

// InsertRequestStage adds a stage to a line.
func (tx *TenantTx) InsertRequestStage(s *RequestStage) error {
	_, err := tx.exec(stagesInsert, sql.Named("line_id", s.LineID), sql.Named("idx", s.Idx), sql.Named("kind", s.Kind),
		sql.Named("assignee", IP(s.AssigneeID)), sql.Named("status", s.Status), sql.Named("started_at", TP(s.StartedAt)),
		sql.Named("due_at", TP(s.DueAt)))
	return err
}

// RequestStages returns a line's stages in order.
func (tx *TenantTx) RequestStages(lineID string) ([]*RequestStage, error) {
	return collect(tx, scanStage, stagesForLine, sql.Named("line_id", lineID))
}

// WaitingStages returns every stage waiting for a decision.
func (tx *TenantTx) WaitingStages() ([]*RequestStage, error) {
	return collect(tx, scanStage, stagesWaiting)
}

// SaveRequestStage moves a stage from status from to s's state; ErrNotFound
// if it is no longer in from.
func (tx *TenantTx) SaveRequestStage(s *RequestStage, from string) error {
	res, err := tx.exec(stagesSave, sql.Named("line_id", s.LineID), sql.Named("idx", s.Idx), sql.Named("from", from),
		sql.Named("status", s.Status), sql.Named("started_at", TP(s.StartedAt)), sql.Named("due_at", TP(s.DueAt)),
		sql.Named("decided_by", SP(s.DecidedBy)), sql.Named("on_behalf_of", SP(s.OnBehalfOf)),
		sql.Named("decided_at", TP(s.DecidedAt)), sql.Named("reason", SP(s.Reason)))
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

// CloseOpenStages closes a line's queued and waiting stages (the line ended).
func (tx *TenantTx) CloseOpenStages(lineID string) error {
	_, err := tx.exec(stagesCloseOpen, sql.Named("line_id", lineID))
	return err
}

// UsersLinkedTo returns the active platform users who are identityID.
func (tx *TenantTx) UsersLinkedTo(identityID int64) ([]string, error) {
	rows, err := tx.query(usersLinkedTo, sql.Named("identity_id", identityID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// InsertApprovalDelegation records a delegation.
func (tx *TenantTx) InsertApprovalDelegation(d *ApprovalDelegationRow) error {
	_, err := tx.exec(approvalDelegationsInsert, sql.Named("id", d.ID), sql.Named("from_user", d.FromUser), sql.Named("to_user", d.ToUser),
		sql.Named("starts_at", T(d.StartsAt)), sql.Named("ends_at", T(d.EndsAt)), sql.Named("reason", d.Reason),
		sql.Named("created_at", T(d.CreatedAt)))
	return err
}

// ApprovalDelegations lists the delegations a user gave or received ("" for all), newest first.
func (tx *TenantTx) ApprovalDelegations(user string) ([]*ApprovalDelegationRow, error) {
	return collect(tx, scanApprovalDelegation, approvalDelegationsInvolving, sql.Named("user", user))
}

// ApprovalDelegation returns one delegation, or ErrNotFound.
func (tx *TenantTx) ApprovalDelegation(id string) (*ApprovalDelegationRow, error) {
	return one(tx, scanApprovalDelegation, approvalDelegationsGet, sql.Named("id", id))
}

// ActiveApprovalDelegationsTo lists the delegations in force for user at now.
func (tx *TenantTx) ActiveApprovalDelegationsTo(user string, now time.Time) ([]*ApprovalDelegationRow, error) {
	return collect(tx, scanApprovalDelegation, approvalDelegationsActiveTo, sql.Named("user", user), sql.Named("now", T(now)))
}

// RevokeApprovalDelegation ends a delegation; ErrNotFound if unknown or already revoked.
func (tx *TenantTx) RevokeApprovalDelegation(id, by string, at time.Time) error {
	res, err := tx.exec(approvalDelegationsRevoke, sql.Named("id", id), sql.Named("by", by), sql.Named("at", T(at)))
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
