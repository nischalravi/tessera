package store

import (
	"database/sql"
	"time"
)

// Who asked for the last disable of an account through the account route (schema/0965_account_disable_requests.sql,
// issue #915): the four-eyes check of its re-enable reads it.

// AccountDisableRequest is that record.
type AccountDisableRequest struct {
	AccountID   int64
	RequestedBy string
	// RequestedByUser is the platform user, nil when a non-user principal asked.
	RequestedByUser *string
	RequestedAt     time.Time
}

var (
	accountDisableReqUpsert = tq("account_disable_requests.upsert", `
		INSERT INTO account_disable_requests (tenant_id, account_id, requested_by, requested_by_user_id, requested_at)
		VALUES (@tenant, @account_id, @requested_by, @requested_by_user_id, @requested_at)
		ON CONFLICT (tenant_id, account_id) DO UPDATE SET requested_by = excluded.requested_by,
			requested_by_user_id = excluded.requested_by_user_id, requested_at = excluded.requested_at`)
	accountDisableReqGet = tq("account_disable_requests.get", `
		SELECT r.account_id, r.requested_by, r.requested_by_user_id, r.requested_at FROM account_disable_requests r
		WHERE r.tenant_id = @tenant AND r.account_id = @account_id`)
)

// RecordAccountDisableRequest notes who asked to disable the account, replacing an earlier request.
func (tx *TenantTx) RecordAccountDisableRequest(accountID int64, by string, byUser *string, at time.Time) error {
	var u any
	if byUser != nil {
		u = *byUser
	}
	_, err := tx.exec(accountDisableReqUpsert, sql.Named("account_id", accountID), sql.Named("requested_by", by),
		sql.Named("requested_by_user_id", u), sql.Named("requested_at", RT(at)))
	return err
}

// AccountDisableRequest returns who last asked to disable the account, or ErrNotFound.
func (tx *TenantTx) AccountDisableRequest(accountID int64) (*AccountDisableRequest, error) {
	var r AccountDisableRequest
	var user sql.NullString
	var at string
	err := tx.queryRow(accountDisableReqGet, sql.Named("account_id", accountID)).Scan(&r.AccountID, &r.RequestedBy, &user, &at)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if user.Valid {
		r.RequestedByUser = &user.String
	}
	if r.RequestedAt, err = ParseRT(at); err != nil {
		return nil, err
	}
	return &r, nil
}
