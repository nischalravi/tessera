package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Pending four-eyes revokes of OAuth apps (schema/0470_oauth_revoke_requests.sql,
// issue #107): the first admin's request waits here, a second admin's
// identical request executes it.

// OAuth revoke request scopes and statuses.
const (
	OAuthRevokeApp    = "app"
	OAuthRevokeVendor = "vendor"

	OAuthRevokePending  = "pending"
	OAuthRevokeExecuted = "executed"
	OAuthRevokeExpired  = "expired"
)

// OAuthRevokeRequest is one request.
type OAuthRevokeRequest struct {
	ID                string
	Scope             string // app, vendor
	Target            string // the app id, or the lower-cased vendor
	Reason            string
	Apps, Grants      int
	RequestedByUserID uuid.UUID
	RequestedBy       string
	RequestedAt       time.Time
	ExpiresAt         time.Time
	Status            string
	DecidedBy         *string
	DecidedAt         *time.Time
}

const oauthRevokeReqCols = `r.id, r.scope, r.target, r.reason, r.apps, r.grants, r.requested_by_user_id, r.requested_by,
	r.requested_at, r.expires_at, r.status, r.decided_by, r.decided_at`

var (
	oauthRevokeReqInsert = tq("oauth_revoke_requests.insert", `
		INSERT INTO oauth_revoke_requests (id, tenant_id, scope, target, reason, apps, grants, requested_by_user_id, requested_by,
			requested_at, expires_at)
		VALUES (@id, @tenant, @scope, @target, @reason, @apps, @grants, @requested_by_user_id, @requested_by,
			@requested_at, @expires_at)`)
	oauthRevokeReqPending = tq("oauth_revoke_requests.pending", `
		SELECT `+oauthRevokeReqCols+` FROM oauth_revoke_requests r
		WHERE r.tenant_id = @tenant AND r.scope = @scope AND r.target = @target AND r.status = 'pending' AND r.expires_at > @now
		ORDER BY r.requested_at DESC, r.id LIMIT 1`)
	oauthRevokeReqList = tq("oauth_revoke_requests.list_pending", `
		SELECT `+oauthRevokeReqCols+` FROM oauth_revoke_requests r
		WHERE r.tenant_id = @tenant AND r.status = 'pending' AND r.expires_at > @now
		ORDER BY r.requested_at, r.id`)
	oauthRevokeReqExpire = tq("oauth_revoke_requests.expire", `
		UPDATE oauth_revoke_requests SET status = 'expired'
		WHERE tenant_id = @tenant AND status = 'pending' AND expires_at <= @now`)
	oauthRevokeReqExecute = tq("oauth_revoke_requests.execute", `
		UPDATE oauth_revoke_requests SET status = 'executed', decided_by_user_id = @decided_by_user_id, decided_by = @decided_by,
			decided_at = @decided_at
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
)

func scanOAuthRevokeRequest(s scanner) (*OAuthRevokeRequest, error) {
	var r OAuthRevokeRequest
	var by, at, exp string
	var decidedBy, decidedAt sql.NullString
	if err := s.Scan(&r.ID, &r.Scope, &r.Target, &r.Reason, &r.Apps, &r.Grants, &by, &r.RequestedBy, &at, &exp, &r.Status,
		&decidedBy, &decidedAt); err != nil {
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
	r.DecidedBy = strp(decidedBy)
	r.DecidedAt, err = rtp(decidedAt)
	return &r, err
}

// InsertOAuthRevokeRequest records a pending request and sets r.ID. The guard
// triggers refuse another tenant's user.
func (tx *TenantTx) InsertOAuthRevokeRequest(r *OAuthRevokeRequest) error {
	r.ID = NewID()
	r.Status = OAuthRevokePending
	_, err := tx.exec(oauthRevokeReqInsert, sql.Named("id", r.ID), sql.Named("scope", r.Scope), sql.Named("target", r.Target),
		sql.Named("reason", r.Reason), sql.Named("apps", r.Apps), sql.Named("grants", r.Grants),
		sql.Named("requested_by_user_id", r.RequestedByUserID.String()), sql.Named("requested_by", r.RequestedBy),
		sql.Named("requested_at", RT(r.RequestedAt)), sql.Named("expires_at", RT(r.ExpiresAt)))
	return err
}

// PendingOAuthRevokeRequest returns the newest unexpired pending request for
// the scope and target, or ErrNotFound.
func (tx *TenantTx) PendingOAuthRevokeRequest(scope, target string, now time.Time) (*OAuthRevokeRequest, error) {
	return one(tx, scanOAuthRevokeRequest, oauthRevokeReqPending, sql.Named("scope", scope), sql.Named("target", target),
		sql.Named("now", RT(now)))
}

// PendingOAuthRevokeRequests lists the unexpired pending requests, oldest first.
func (tx *TenantTx) PendingOAuthRevokeRequests(now time.Time) ([]*OAuthRevokeRequest, error) {
	return collect(tx, scanOAuthRevokeRequest, oauthRevokeReqList, sql.Named("now", RT(now)))
}

// ExpireOAuthRevokeRequests marks the pending requests past their time expired.
func (tx *TenantTx) ExpireOAuthRevokeRequests(now time.Time) error {
	_, err := tx.exec(oauthRevokeReqExpire, sql.Named("now", RT(now)))
	return err
}

// ExecuteOAuthRevokeRequest marks a pending request executed by a second
// admin. ErrNotFound when it is not pending (or not the tenant's).
func (tx *TenantTx) ExecuteOAuthRevokeRequest(id string, by uuid.UUID, byName string, now time.Time) error {
	return tx.execOne(oauthRevokeReqExecute, sql.Named("id", id), sql.Named("decided_by_user_id", by.String()),
		sql.Named("decided_by", byName), sql.Named("decided_at", RT(now)))
}
