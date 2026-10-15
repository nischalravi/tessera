package store

import (
	"database/sql"
	"time"
)

// Two-person activation requests (schema/0208_activation_requests.sql,
// deployment readiness DR-10). Only internal/readiness decides when a request
// may be made, approved or applied; the store keeps the rows.

// Activation request statuses.
const (
	ActivationPending   = "pending"
	ActivationApplied   = "applied"
	ActivationRejected  = "rejected"
	ActivationCancelled = "cancelled"
	ActivationExpired   = "expired"
)

// ActivationRequest asks for a write-enabled revision to be activated. The
// *Key fields are stable principal keys (user:<uuid>), used for the
// two-person comparison; the display fields are for people to read.
type ActivationRequest struct {
	ID, ConnectionID, RevisionID string
	ConfigHash                   string
	WriteMode                    string
	Status                       string
	RequestedByKey               string
	RequestedBy                  string
	RequestedAt, ExpiresAt       time.Time
	DecidedByKey, DecidedBy      string
	DecidedAt                    *time.Time
	DecisionNote                 string
}

const activationCols = `a.id, a.connection_id, a.revision_id, a.config_hash, a.write_mode, a.status, a.requested_by_key,
	a.requested_by, a.requested_at, a.expires_at, a.decided_by_key, a.decided_by, a.decided_at, a.decision_note`

var (
	activationInsert = tq("connection_activation_requests.insert", `
		INSERT INTO connection_activation_requests (id, tenant_id, connection_id, revision_id, config_hash, write_mode,
			status, requested_by_key, requested_by, requested_at, expires_at)
		VALUES (@id, @tenant, @connection_id, @revision_id, @config_hash, @write_mode, 'pending', @requested_by_key,
			@requested_by, @requested_at, @expires_at)`)
	activationPendingForConn = tq("connection_activation_requests.pending_for_connection", `
		SELECT `+activationCols+` FROM connection_activation_requests a
		WHERE a.tenant_id = @tenant AND a.connection_id = @connection_id AND a.status = 'pending'
		ORDER BY a.requested_at DESC LIMIT 1`)
	activationLatestForConn = tq("connection_activation_requests.latest_for_connection", `
		SELECT `+activationCols+` FROM connection_activation_requests a
		WHERE a.tenant_id = @tenant AND a.connection_id = @connection_id
		ORDER BY a.requested_at DESC, a.rowid DESC LIMIT 1`)
	// decide moves a pending request to its final status. The status guard
	// makes a second decision of the same request a no-op (ErrNotFound).
	activationDecide = tq("connection_activation_requests.decide", `
		UPDATE connection_activation_requests SET status = @status, decided_by_key = @decided_by_key,
			decided_by = @decided_by, decided_at = @decided_at, decision_note = @decision_note
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
)

func scanActivation(s scanner) (*ActivationRequest, error) {
	var a ActivationRequest
	var reqAt, expAt string
	var dk, db, dat sql.NullString
	if err := s.Scan(&a.ID, &a.ConnectionID, &a.RevisionID, &a.ConfigHash, &a.WriteMode, &a.Status, &a.RequestedByKey,
		&a.RequestedBy, &reqAt, &expAt, &dk, &db, &dat, &a.DecisionNote); err != nil {
		return nil, err
	}
	var err error
	if a.RequestedAt, err = ParseRT(reqAt); err != nil {
		return nil, err
	}
	if a.ExpiresAt, err = ParseRT(expAt); err != nil {
		return nil, err
	}
	a.DecidedByKey, a.DecidedBy = dk.String, db.String
	if dat.Valid {
		t, err := ParseRT(dat.String)
		if err != nil {
			return nil, err
		}
		a.DecidedAt = &t
	}
	return &a, nil
}

// InsertActivationRequest records a pending request. A second open request for
// the same revision violates the unique index.
func (tx *TenantTx) InsertActivationRequest(a *ActivationRequest) error {
	_, err := tx.exec(activationInsert, sql.Named("id", a.ID), sql.Named("connection_id", a.ConnectionID),
		sql.Named("revision_id", a.RevisionID), sql.Named("config_hash", a.ConfigHash),
		sql.Named("write_mode", a.WriteMode), sql.Named("requested_by_key", a.RequestedByKey),
		sql.Named("requested_by", a.RequestedBy), sql.Named("requested_at", RT(a.RequestedAt)),
		sql.Named("expires_at", RT(a.ExpiresAt)))
	return err
}

// PendingActivationRequest returns the connection's open request or ErrNotFound.
func (tx *TenantTx) PendingActivationRequest(connectionID string) (*ActivationRequest, error) {
	return one(tx, scanActivation, activationPendingForConn, sql.Named("connection_id", connectionID))
}

// LatestActivationRequest returns the connection's newest request, whatever
// its status, or ErrNotFound.
func (tx *TenantTx) LatestActivationRequest(connectionID string) (*ActivationRequest, error) {
	return one(tx, scanActivation, activationLatestForConn, sql.Named("connection_id", connectionID))
}

// DecideActivationRequest sets the final status of a pending request;
// ErrNotFound if it is not pending (or not this tenant's).
func (tx *TenantTx) DecideActivationRequest(id, status, byKey, by, note string, at time.Time) error {
	return tx.execOne(activationDecide, sql.Named("id", id), sql.Named("status", status),
		sql.Named("decided_by_key", byKey), sql.Named("decided_by", by), sql.Named("decided_at", RT(at)),
		sql.Named("decision_note", note))
}
