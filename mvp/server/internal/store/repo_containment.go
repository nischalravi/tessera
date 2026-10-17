package store

import (
	"database/sql"
	"time"
)

// The containment credential (the provider token the kill switch uses) lives
// in the shared sealed store, repo_credentials.go, with purpose "containment".

// ---------------------------------------------------------------- retries

// Containment retry statuses.
const (
	RetryPending   = "pending"
	RetrySucceeded = "succeeded"
	RetryGaveUp    = "gave_up"
)

// ContainmentRetry is a durable retry task for one failed containment step
// (schema/0206_containment_retries.sql).
type ContainmentRetry struct {
	ID            string
	IdentityID    int64
	AccountID     int64
	ConnectionID  *string
	System        string
	Account       string // the account's username, for display
	Action        string // revoke_sessions or revoke_grants
	Trigger       string // leaver, manual, agent
	Status        string
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

const retryCols = `r.id, r.identity_id, r.account_id, r.connection_id, r.system, r.account_label, r.action, r.trigger,
	r.status, r.attempts, r.next_attempt_at, r.last_error, r.created_at, r.updated_at`

var (
	retriesInsert = tq("containment_retries.insert", `
		INSERT INTO containment_retries (id, tenant_id, identity_id, account_id, connection_id, system, account_label,
			action, trigger, status, attempts, next_attempt_at, last_error, created_at, updated_at)
		VALUES (@id, @tenant, @identity_id, @account_id, @connection_id, @system, @account_label, @action, @trigger,
			'pending', 0, @next_attempt_at, @last_error, @now, @now)`)
	retriesGet = tq("containment_retries.get", `
		SELECT `+retryCols+` FROM containment_retries r WHERE r.tenant_id = @tenant AND r.id = @id`)
	retriesByIdentity = tq("containment_retries.by_identity", `
		SELECT `+retryCols+` FROM containment_retries r WHERE r.tenant_id = @tenant AND r.identity_id = @identity_id
		ORDER BY r.created_at, r.id`)
	retriesDue = tq("containment_retries.due", `
		SELECT `+retryCols+` FROM containment_retries r
		WHERE r.tenant_id = @tenant AND r.status = 'pending' AND r.next_attempt_at <= @now
		ORDER BY r.next_attempt_at, r.id LIMIT 50`)
	retriesOpen = tq("containment_retries.open", `
		SELECT `+retryCols+` FROM containment_retries r
		WHERE r.tenant_id = @tenant AND r.status = 'pending' AND r.account_id = @account_id AND r.action = @action`)
	retriesUpdate = tq("containment_retries.update", `
		UPDATE containment_retries SET status = @status, attempts = @attempts, next_attempt_at = @next_attempt_at,
			last_error = @last_error, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
)

func scanRetry(s scanner) (*ContainmentRetry, error) {
	var r ContainmentRetry
	var conn sql.NullString
	var next, created, updated string
	if err := s.Scan(&r.ID, &r.IdentityID, &r.AccountID, &conn, &r.System, &r.Account, &r.Action, &r.Trigger,
		&r.Status, &r.Attempts, &next, &r.LastError, &created, &updated); err != nil {
		return nil, err
	}
	r.ConnectionID = strp(conn)
	var err error
	if r.NextAttemptAt, err = ParseRT(next); err != nil {
		return nil, err
	}
	if r.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	r.UpdatedAt, err = ParseRT(updated)
	return &r, err
}

// InsertContainmentRetry adds a pending retry task (r.ID is set when empty).
func (tx *TenantTx) InsertContainmentRetry(r *ContainmentRetry, now time.Time) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	_, err := tx.exec(retriesInsert, sql.Named("id", r.ID), sql.Named("identity_id", r.IdentityID),
		sql.Named("account_id", r.AccountID), sql.Named("connection_id", SP(r.ConnectionID)), sql.Named("system", r.System),
		sql.Named("account_label", r.Account), sql.Named("action", r.Action), sql.Named("trigger", r.Trigger),
		sql.Named("next_attempt_at", RT(r.NextAttemptAt)), sql.Named("last_error", r.LastError), sql.Named("now", RT(now)))
	return err
}

// ContainmentRetry returns one retry task or ErrNotFound.
func (tx *TenantTx) ContainmentRetry(id string) (*ContainmentRetry, error) {
	return one(tx, scanRetry, retriesGet, sql.Named("id", id))
}

// ContainmentRetriesFor lists an identity's retry tasks, oldest first.
func (tx *TenantTx) ContainmentRetriesFor(identityID int64) ([]*ContainmentRetry, error) {
	return collect(tx, scanRetry, retriesByIdentity, sql.Named("identity_id", identityID))
}

// DueContainmentRetries lists pending tasks whose next attempt is due (at most 50).
func (tx *TenantTx) DueContainmentRetries(now time.Time) ([]*ContainmentRetry, error) {
	return collect(tx, scanRetry, retriesDue, sql.Named("now", RT(now)))
}

// OpenContainmentRetry returns the pending task of an account's step, or ErrNotFound.
func (tx *TenantTx) OpenContainmentRetry(accountID int64, action string) (*ContainmentRetry, error) {
	return one(tx, scanRetry, retriesOpen, sql.Named("account_id", accountID), sql.Named("action", action))
}

// UpdateContainmentRetry records an attempt on a pending task (ErrNotFound
// when it is not pending any more).
func (tx *TenantTx) UpdateContainmentRetry(id, status string, attempts int, next time.Time, lastError string, now time.Time) error {
	return tx.execOne(retriesUpdate, sql.Named("id", id), sql.Named("status", status), sql.Named("attempts", attempts),
		sql.Named("next_attempt_at", RT(next)), sql.Named("last_error", lastError), sql.Named("now", RT(now)))
}
