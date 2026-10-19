package store

import (
	"database/sql"
	"time"
)

// Removal requests (schema/0311_removal_requests.sql).

// RemovalRequest is a request to remove one grant (account -> group) a
// person holds.
type RemovalRequest struct {
	ID             string
	BeneficiaryID  int64
	AccountID      int64
	GroupID        int64
	RequestedBy    string
	Justification  string
	Status         string // pending, approved, denied, cancelled (the Request* constants)
	RequestedAt    time.Time
	DecidedBy      *string
	DecidedAt      *time.Time
	DecisionReason *string
	Outcome        *string // set on approval: revoked, request_removed, already_removed
}

// RemovalRequestFilter selects removal requests; zero fields match everything.
type RemovalRequestFilter struct {
	Status            string
	InvolvingUser     string // requested by this user ...
	InvolvingIdentity int64  // ... or for this identity
}

const rmqCols = `q.id, q.beneficiary_id, q.account_id, q.group_id, q.requested_by, q.justification, q.status,
	q.requested_at, q.decided_by, q.decided_at, q.decision_reason, q.outcome`

var (
	rmqInsert = tq("removal_requests.insert", `
		INSERT INTO removal_requests (id, tenant_id, beneficiary_id, account_id, group_id, requested_by, justification,
			status, requested_at)
		VALUES (@id, @tenant, @beneficiary_id, @account_id, @group_id, @requested_by, @justification, 'pending',
			@requested_at)`)
	rmqGet = tq("removal_requests.get", `
		SELECT `+rmqCols+` FROM removal_requests q WHERE q.tenant_id = @tenant AND q.id = @id`)
	rmqFiltered = tq("removal_requests.filtered", `
		SELECT `+rmqCols+` FROM removal_requests q WHERE q.tenant_id = @tenant
			AND (@status = '' OR q.status = @status)
			AND ((@inv_user = '' AND @inv_identity = 0) OR q.requested_by = @inv_user OR q.beneficiary_id = @inv_identity)
		ORDER BY q.requested_at DESC, q.id LIMIT 500`)
	rmqSave = tq("removal_requests.save", `
		UPDATE removal_requests SET status = @status, decided_by = @decided_by, decided_at = @decided_at,
			decision_reason = @decision_reason, outcome = @outcome
		WHERE tenant_id = @tenant AND id = @id AND status = @from`)
)

func scanRemovalRequest(s scanner) (*RemovalRequest, error) {
	var q RemovalRequest
	var at, decAt nullTime
	var decBy, reason, outcome sql.NullString
	if err := s.Scan(&q.ID, &q.BeneficiaryID, &q.AccountID, &q.GroupID, &q.RequestedBy, &q.Justification, &q.Status,
		&at, &decBy, &decAt, &reason, &outcome); err != nil {
		return nil, err
	}
	q.DecidedBy, q.DecisionReason, q.Outcome = strp(decBy), strp(reason), strp(outcome)
	var err error
	if q.RequestedAt, err = at.val(); err != nil {
		return nil, err
	}
	q.DecidedAt, err = decAt.ptr()
	return &q, err
}

// InsertRemovalRequest files a pending removal request. ErrDuplicate when the
// person already has one pending for the group.
func (tx *TenantTx) InsertRemovalRequest(q *RemovalRequest) error {
	if q.ID == "" {
		q.ID = NewID()
	}
	_, err := tx.exec(rmqInsert, sql.Named("id", q.ID), sql.Named("beneficiary_id", q.BeneficiaryID),
		sql.Named("account_id", q.AccountID), sql.Named("group_id", q.GroupID), sql.Named("requested_by", q.RequestedBy),
		sql.Named("justification", q.Justification), sql.Named("requested_at", T(q.RequestedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// RemovalRequest returns one removal request, or ErrNotFound.
func (tx *TenantTx) RemovalRequest(id string) (*RemovalRequest, error) {
	return one(tx, scanRemovalRequest, rmqGet, sql.Named("id", id))
}

// RemovalRequests returns the removal requests matching f, newest first (at most 500).
func (tx *TenantTx) RemovalRequests(f RemovalRequestFilter) ([]*RemovalRequest, error) {
	return collect(tx, scanRemovalRequest, rmqFiltered, sql.Named("status", f.Status),
		sql.Named("inv_user", f.InvolvingUser), sql.Named("inv_identity", f.InvolvingIdentity))
}

// SaveRemovalRequest moves a request from status from to q's state;
// ErrNotFound if it is no longer in from.
func (tx *TenantTx) SaveRemovalRequest(q *RemovalRequest, from string) error {
	return tx.execOne(rmqSave, sql.Named("id", q.ID), sql.Named("from", from), sql.Named("status", q.Status),
		sql.Named("decided_by", SP(q.DecidedBy)), sql.Named("decided_at", TP(q.DecidedAt)),
		sql.Named("decision_reason", SP(q.DecisionReason)), sql.Named("outcome", SP(q.Outcome)))
}
