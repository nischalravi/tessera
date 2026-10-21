package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Pending account pins and releases (schema/0500_account_link_requests.sql,
// issue #376): the first admin's request to pin a connector account to an
// identity, or to release the pin, which a second admin's identical request
// applies.

// Actions of an AccountLinkRequest.
const (
	AccountLinkActionLink    = "link"
	AccountLinkActionRelease = "release"
)

// AccountLinkRequest is one pending change. IdentityID is set for a link
// request only; PreviousIdentityID is the account's identity when the request
// was made.
type AccountLinkRequest struct {
	AccountID          int64
	Action             string
	IdentityID         *int64
	PreviousIdentityID *int64
	Reason             string
	RequestedByUserID  uuid.UUID
	RequestedBy        string
	RequestedAt        time.Time
	ExpiresAt          time.Time
}

// AccountLinkRequestRow is a pending request with the names an approver sees.
type AccountLinkRequestRow struct {
	AccountLinkRequest
	System       string
	Username     string
	IdentityName string
	PreviousName string
}

const accountLinkReqCols = `r.account_id, r.action, r.identity_id, r.previous_identity_id, r.reason, r.requested_by_user_id,
	r.requested_by, r.requested_at, r.expires_at`

var (
	accountLinkReqGet = tq("account_link_requests.get", `
		SELECT `+accountLinkReqCols+` FROM account_link_requests r WHERE r.tenant_id = @tenant AND r.account_id = @account_id`)
	accountLinkReqList = tq("account_link_requests.list", `
		SELECT `+accountLinkReqCols+`, a.system, a.username, COALESCE(i.name, ''), COALESCE(pi.name, '')
		FROM account_link_requests r
		JOIN accounts a ON a.tenant_id = @tenant AND a.id = r.account_id
		LEFT JOIN identities i ON i.tenant_id = @tenant AND i.id = r.identity_id
		LEFT JOIN identities pi ON pi.tenant_id = @tenant AND pi.id = r.previous_identity_id
		WHERE r.tenant_id = @tenant AND r.expires_at > @now ORDER BY r.requested_at, r.account_id`)
	accountLinkReqPut = tq("account_link_requests.put", `
		INSERT INTO account_link_requests (tenant_id, account_id, action, identity_id, previous_identity_id, reason,
			requested_by_user_id, requested_by, requested_at, expires_at)
		VALUES (@tenant, @account_id, @action, @identity_id, @previous_identity_id, @reason, @requested_by_user_id,
			@requested_by, @requested_at, @expires_at)
		ON CONFLICT (tenant_id, account_id) DO UPDATE SET action = excluded.action, identity_id = excluded.identity_id,
			previous_identity_id = excluded.previous_identity_id, reason = excluded.reason,
			requested_by_user_id = excluded.requested_by_user_id, requested_by = excluded.requested_by,
			requested_at = excluded.requested_at, expires_at = excluded.expires_at`)
	accountLinkReqDelete = tq("account_link_requests.delete", `
		DELETE FROM account_link_requests WHERE tenant_id = @tenant AND account_id = @account_id`)
)

func scanAccountLinkRequest(s scanner, extra ...any) (*AccountLinkRequest, error) {
	var r AccountLinkRequest
	var by, at, exp string
	var ident, prev sql.NullInt64
	dest := append([]any{&r.AccountID, &r.Action, &ident, &prev, &r.Reason, &by, &r.RequestedBy, &at, &exp}, extra...)
	if err := s.Scan(dest...); err != nil {
		return nil, err
	}
	var err error
	if r.RequestedByUserID, err = uuid.Parse(by); err != nil {
		return nil, err
	}
	if r.RequestedAt, err = ParseRT(at); err != nil {
		return nil, err
	}
	if r.ExpiresAt, err = ParseRT(exp); err != nil {
		return nil, err
	}
	r.IdentityID, r.PreviousIdentityID = intp(ident), intp(prev)
	return &r, nil
}

// AccountLinkRequest returns the account's pending change, or ErrNotFound.
func (tx *TenantTx) AccountLinkRequest(accountID int64) (*AccountLinkRequest, error) {
	return one(tx, func(s scanner) (*AccountLinkRequest, error) { return scanAccountLinkRequest(s) },
		accountLinkReqGet, sql.Named("account_id", accountID))
}

// PutAccountLinkRequest records (or replaces) the account's pending change.
// The guard triggers refuse another tenant's account, identity or user.
func (tx *TenantTx) PutAccountLinkRequest(r *AccountLinkRequest) error {
	_, err := tx.exec(accountLinkReqPut, sql.Named("account_id", r.AccountID), sql.Named("action", r.Action),
		sql.Named("identity_id", IP(r.IdentityID)), sql.Named("previous_identity_id", IP(r.PreviousIdentityID)),
		sql.Named("reason", r.Reason), sql.Named("requested_by_user_id", r.RequestedByUserID.String()),
		sql.Named("requested_by", r.RequestedBy), sql.Named("requested_at", RT(r.RequestedAt)),
		sql.Named("expires_at", RT(r.ExpiresAt)))
	return err
}

// DeleteAccountLinkRequest removes the account's pending change, if any.
func (tx *TenantTx) DeleteAccountLinkRequest(accountID int64) error {
	_, err := tx.exec(accountLinkReqDelete, sql.Named("account_id", accountID))
	return err
}

// AccountLinkRequests lists the tenant's unexpired pending changes, oldest first.
func (tx *TenantTx) AccountLinkRequests(now time.Time) ([]*AccountLinkRequestRow, error) {
	return collect(tx, func(sc scanner) (*AccountLinkRequestRow, error) {
		var row AccountLinkRequestRow
		r, err := scanAccountLinkRequest(sc, &row.System, &row.Username, &row.IdentityName, &row.PreviousName)
		if err != nil {
			return nil, err
		}
		row.AccountLinkRequest = *r
		return &row, nil
	}, accountLinkReqList, sql.Named("now", RT(now)))
}
