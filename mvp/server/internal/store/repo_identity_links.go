package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Pending identity-link changes (schema/0362_identity_link_requests.sql,
// issue #357): the first admin's request to change or remove a platform
// user's identity link, which a second admin's identical change applies.

// IdentityLinkRequest is one pending change. IdentityID nil removes the
// link; PreviousIdentityID is the link the request was made against.
type IdentityLinkRequest struct {
	UserID             uuid.UUID
	IdentityID         *int64
	PreviousIdentityID *int64
	RequestedByUserID  uuid.UUID
	RequestedBy        string
	RequestedAt        time.Time
	ExpiresAt          time.Time
}

const identityLinkCols = `r.user_id, r.identity_id, r.previous_identity_id, r.requested_by_user_id, r.requested_by,
	r.requested_at, r.expires_at`

var (
	identityLinkGet = tq("identity_link_requests.get", `
		SELECT `+identityLinkCols+` FROM identity_link_requests r WHERE r.tenant_id = @tenant AND r.user_id = @user_id`)
	identityLinkPut = tq("identity_link_requests.put", `
		INSERT INTO identity_link_requests (tenant_id, user_id, identity_id, previous_identity_id, requested_by_user_id,
			requested_by, requested_at, expires_at)
		VALUES (@tenant, @user_id, @identity_id, @previous_identity_id, @requested_by_user_id, @requested_by,
			@requested_at, @expires_at)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET identity_id = excluded.identity_id,
			previous_identity_id = excluded.previous_identity_id, requested_by_user_id = excluded.requested_by_user_id,
			requested_by = excluded.requested_by, requested_at = excluded.requested_at, expires_at = excluded.expires_at`)
	identityLinkDelete = tq("identity_link_requests.delete", `
		DELETE FROM identity_link_requests WHERE tenant_id = @tenant AND user_id = @user_id`)
)

func scanIdentityLinkRequest(s scanner) (*IdentityLinkRequest, error) {
	var r IdentityLinkRequest
	var user, by, at, exp string
	var ident, prev sql.NullInt64
	if err := s.Scan(&user, &ident, &prev, &by, &r.RequestedBy, &at, &exp); err != nil {
		return nil, err
	}
	var err error
	if r.UserID, err = uuid.Parse(user); err != nil {
		return nil, err
	}
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

// IdentityLinkRequest returns the user's pending link change, or ErrNotFound.
func (tx *TenantTx) IdentityLinkRequest(user uuid.UUID) (*IdentityLinkRequest, error) {
	return one(tx, scanIdentityLinkRequest, identityLinkGet, sql.Named("user_id", user.String()))
}

// PutIdentityLinkRequest records (or replaces) the user's pending link
// change. The guard triggers refuse another tenant's user or identity.
func (tx *TenantTx) PutIdentityLinkRequest(r *IdentityLinkRequest) error {
	_, err := tx.exec(identityLinkPut, sql.Named("user_id", r.UserID.String()), sql.Named("identity_id", IP(r.IdentityID)),
		sql.Named("previous_identity_id", IP(r.PreviousIdentityID)),
		sql.Named("requested_by_user_id", r.RequestedByUserID.String()), sql.Named("requested_by", r.RequestedBy),
		sql.Named("requested_at", RT(r.RequestedAt)), sql.Named("expires_at", RT(r.ExpiresAt)))
	return err
}

// DeleteIdentityLinkRequest removes the user's pending link change, if any.
func (tx *TenantTx) DeleteIdentityLinkRequest(user uuid.UUID) error {
	_, err := tx.exec(identityLinkDelete, sql.Named("user_id", user.String()))
	return err
}
