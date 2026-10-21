package store

import (
	"database/sql"
	"time"
)

// Service-account requests (schema/0481_service_account_requests.sql, issue #298). The rules live
// in internal/svcaccounts.

// Service-account request kinds and statuses.
const (
	SAKindCreate   = "create"
	SAKindChange   = "change"
	SAKindTransfer = "transfer"

	SAPending   = "pending"
	SAApproved  = "approved"
	SAFulfilled = "fulfilled"
	SADenied    = "denied"
	SACancelled = "cancelled"
)

// ServiceAccountRequest is a request to create, change or transfer a service account.
type ServiceAccountRequest struct {
	ID                string
	Kind              string
	Status            string
	IdentityID        *int64
	Name              string
	System            string
	Username          string
	Purpose           string
	Description       string
	PrimaryOwnerID    int64
	BackupOwnerID     *int64
	PreviousPrimaryID *int64
	PreviousBackupID  *int64
	Justification     string
	RequestedBy       string
	RequestedAt       time.Time
	DecidedBy         *string
	DecidedAt         *time.Time
	DecisionReason    *string
	ClosedAt          *time.Time
	FulfilledAt       *time.Time
	OpID              *string
}

// SARequestFilter narrows ServiceAccountRequests; zero fields match everything.
type SARequestFilter struct {
	RequestedBy string
	Status      string
	IdentityID  int64
}

const saCols = `q.id, q.kind, q.status, q.identity_id, q.name, q.system, q.username, q.purpose, q.description,
	q.primary_owner_id, q.backup_owner_id, q.previous_primary_id, q.previous_backup_id, q.justification, q.requested_by,
	q.requested_at, q.decided_by, q.decided_at, q.decision_reason, q.closed_at, q.fulfilled_at, q.op_id`

var (
	saReqInsert = tq("service_account_requests.insert", `
		INSERT INTO service_account_requests (id, tenant_id, kind, status, identity_id, name, system, username, purpose, description,
			primary_owner_id, backup_owner_id, previous_primary_id, previous_backup_id, justification, requested_by, requested_at)
		VALUES (@id, @tenant, @kind, @status, @identity_id, @name, @system, @username, @purpose, @description,
			@primary, @backup, @prev_primary, @prev_backup, @justification, @requested_by, @requested_at)`)
	saReqGet  = tq("service_account_requests.get", `SELECT `+saCols+` FROM service_account_requests q WHERE q.tenant_id = @tenant AND q.id = @id`)
	saReqList = tq("service_account_requests.list", `
		SELECT `+saCols+` FROM service_account_requests q WHERE q.tenant_id = @tenant
			AND (@requested_by = '' OR q.requested_by = @requested_by) AND (@status = '' OR q.status = @status)
			AND (@identity_id = 0 OR q.identity_id = @identity_id)
		ORDER BY q.requested_at DESC, q.id`)
	saReqSave = tq("service_account_requests.save", `
		UPDATE service_account_requests SET status = @status, identity_id = @identity_id, decided_by = @decided_by,
			decided_at = @decided_at, decision_reason = @decision_reason, closed_at = @closed_at, fulfilled_at = @fulfilled_at,
			op_id = @op_id
		WHERE tenant_id = @tenant AND id = @id AND status = @from`)
	// a name is taken while an open request for it exists (a create is pending or approved)
	saReqOpenName = tq("service_account_requests.open_create_named", `
		SELECT `+saCols+` FROM service_account_requests q WHERE q.tenant_id = @tenant AND q.kind = 'create'
			AND q.status IN ('pending','approved') AND q.name = @name ORDER BY q.id LIMIT 1`)
	// an account has one open change or transfer at a time
	saReqOpenFor = tq("service_account_requests.open_for_identity", `
		SELECT `+saCols+` FROM service_account_requests q WHERE q.tenant_id = @tenant AND q.identity_id = @identity_id
			AND q.status IN ('pending','approved') ORDER BY q.id LIMIT 1`)
	saReqByOp = tq("service_account_requests.by_op", `
		SELECT `+saCols+` FROM service_account_requests q WHERE q.tenant_id = @tenant AND q.op_id = @op_id`)
)

func scanSARequest(s scanner) (*ServiceAccountRequest, error) {
	var r ServiceAccountRequest
	var identity, backup, prevP, prevB sql.NullInt64
	var requested string
	var decBy, reason, opID sql.NullString
	var decAt, closed, fulfilled nullTime
	if err := s.Scan(&r.ID, &r.Kind, &r.Status, &identity, &r.Name, &r.System, &r.Username, &r.Purpose, &r.Description,
		&r.PrimaryOwnerID, &backup, &prevP, &prevB, &r.Justification, &r.RequestedBy, &requested, &decBy, &decAt, &reason,
		&closed, &fulfilled, &opID); err != nil {
		return nil, err
	}
	r.IdentityID, r.BackupOwnerID, r.PreviousPrimaryID, r.PreviousBackupID = intp(identity), intp(backup), intp(prevP), intp(prevB)
	r.DecidedBy, r.DecisionReason, r.OpID = strp(decBy), strp(reason), strp(opID)
	var err error
	rt := nullTime{sql.NullString{String: requested, Valid: true}}
	if r.RequestedAt, err = rt.val(); err != nil {
		return nil, err
	}
	if r.DecidedAt, err = decAt.ptr(); err != nil {
		return nil, err
	}
	if r.ClosedAt, err = closed.ptr(); err != nil {
		return nil, err
	}
	r.FulfilledAt, err = fulfilled.ptr()
	return &r, err
}

// InsertServiceAccountRequest files a request.
func (tx *TenantTx) InsertServiceAccountRequest(r *ServiceAccountRequest) error {
	_, err := tx.exec(saReqInsert, sql.Named("id", r.ID), sql.Named("kind", r.Kind), sql.Named("status", r.Status),
		sql.Named("identity_id", IP(r.IdentityID)), sql.Named("name", r.Name), sql.Named("system", r.System),
		sql.Named("username", r.Username), sql.Named("purpose", r.Purpose), sql.Named("description", r.Description),
		sql.Named("primary", r.PrimaryOwnerID), sql.Named("backup", IP(r.BackupOwnerID)),
		sql.Named("prev_primary", IP(r.PreviousPrimaryID)), sql.Named("prev_backup", IP(r.PreviousBackupID)),
		sql.Named("justification", r.Justification), sql.Named("requested_by", r.RequestedBy),
		sql.Named("requested_at", T(r.RequestedAt)))
	return err
}

// ServiceAccountRequest returns one by id; ErrNotFound if it is not the tenant's.
func (tx *TenantTx) ServiceAccountRequest(id string) (*ServiceAccountRequest, error) {
	return one(tx, scanSARequest, saReqGet, sql.Named("id", id))
}

// ServiceAccountRequests lists requests, newest first.
func (tx *TenantTx) ServiceAccountRequests(f SARequestFilter) ([]*ServiceAccountRequest, error) {
	return collect(tx, scanSARequest, saReqList, sql.Named("requested_by", f.RequestedBy), sql.Named("status", f.Status),
		sql.Named("identity_id", f.IdentityID))
}

// SaveServiceAccountRequest writes a request's state; ErrNotFound unless it is still in status from.
func (tx *TenantTx) SaveServiceAccountRequest(r *ServiceAccountRequest, from string) error {
	res, err := tx.exec(saReqSave, sql.Named("id", r.ID), sql.Named("from", from), sql.Named("status", r.Status),
		sql.Named("identity_id", IP(r.IdentityID)), sql.Named("decided_by", SP(r.DecidedBy)), sql.Named("decided_at", TP(r.DecidedAt)),
		sql.Named("decision_reason", SP(r.DecisionReason)), sql.Named("closed_at", TP(r.ClosedAt)),
		sql.Named("fulfilled_at", TP(r.FulfilledAt)), sql.Named("op_id", SP(r.OpID)))
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

// OpenServiceAccountCreate returns an open create request for the name; ErrNotFound if none.
func (tx *TenantTx) OpenServiceAccountCreate(name string) (*ServiceAccountRequest, error) {
	return one(tx, scanSARequest, saReqOpenName, sql.Named("name", name))
}

// OpenServiceAccountRequestFor returns the open request about an account; ErrNotFound if none.
func (tx *TenantTx) OpenServiceAccountRequestFor(identityID int64) (*ServiceAccountRequest, error) {
	return one(tx, scanSARequest, saReqOpenFor, sql.Named("identity_id", identityID))
}

// ServiceAccountRequestByOp returns the request whose provisioning operation is opID.
func (tx *TenantTx) ServiceAccountRequestByOp(opID string) (*ServiceAccountRequest, error) {
	return one(tx, scanSARequest, saReqByOp, sql.Named("op_id", opID))
}
