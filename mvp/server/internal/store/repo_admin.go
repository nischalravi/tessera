package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------- bootstrap_invitations (§15.3)

const invCols = `b.id, b.tenant_id, b.code_hash, b.idp_connection_id, b.email, b.role, b.created_by, b.created_at,
	b.expires_at, b.consumed_at, b.consumed_by_user_id`

var (
	invInsert = tq("bootstrap_invitations.insert", `
		INSERT INTO bootstrap_invitations (id, tenant_id, code_hash, idp_connection_id, email, role, created_by,
			created_at, expires_at)
		VALUES (@id, @tenant, @code_hash, @idp_connection_id, @email, @role, @created_by, @created_at, @expires_at)`)
	invGet = tq("bootstrap_invitations.get", `
		SELECT `+invCols+` FROM bootstrap_invitations b WHERE b.tenant_id = @tenant AND b.id = @id`)
	invByCode = tq("bootstrap_invitations.by_code_hash", `
		SELECT `+invCols+` FROM bootstrap_invitations b WHERE b.tenant_id = @tenant AND b.code_hash = @code_hash`)
	// single use: only an unconsumed, unexpired invitation can be consumed
	invConsume = tq("bootstrap_invitations.consume", `
		UPDATE bootstrap_invitations SET consumed_at = @at, consumed_by_user_id = @user_id
		WHERE tenant_id = @tenant AND id = @id AND consumed_at IS NULL AND expires_at > @at`)
)

func scanInvitation(s scanner) (*BootstrapInvitation, error) {
	var b BootstrapInvitation
	var id, tid, conn, created, expires string
	var consumed, by sql.NullString
	if err := s.Scan(&id, &tid, &b.CodeHash, &conn, &b.Email, &b.Role, &b.CreatedBy, &created, &expires,
		&consumed, &by); err != nil {
		return nil, err
	}
	var err error
	if b.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if b.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if b.IdPConnectionID, err = uuid.Parse(conn); err != nil {
		return nil, err
	}
	if by.Valid {
		u, err := uuid.Parse(by.String)
		if err != nil {
			return nil, err
		}
		b.ConsumedByUserID = &u
	}
	if b.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if b.ExpiresAt, err = ParseRT(expires); err != nil {
		return nil, err
	}
	b.ConsumedAt, err = rtp(consumed)
	return &b, err
}

// InsertBootstrapInvitation stores an invitation (CodeHash is the SHA-256
// hex of the code; the code itself is never stored).
func (tx *TenantTx) InsertBootstrapInvitation(b *BootstrapInvitation) error {
	if err := tx.own(b.TenantID); err != nil {
		return err
	}
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	if b.Role == "" {
		b.Role = RoleTenantAdmin
	}
	_, err := tx.exec(invInsert, sql.Named("id", b.ID.String()), sql.Named("code_hash", b.CodeHash),
		sql.Named("idp_connection_id", b.IdPConnectionID.String()), sql.Named("email", b.Email),
		sql.Named("role", b.Role), sql.Named("created_by", b.CreatedBy), sql.Named("created_at", RT(b.CreatedAt)),
		sql.Named("expires_at", RT(b.ExpiresAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// BootstrapInvitation returns one of this tenant's invitations.
func (tx *TenantTx) BootstrapInvitation(id uuid.UUID) (*BootstrapInvitation, error) {
	return one(tx, scanInvitation, invGet, sql.Named("id", id.String()))
}

// BootstrapInvitationByCodeHash finds this tenant's invitation with the code
// hash (ErrNotFound when none: another tenant's code is not found either).
func (tx *TenantTx) BootstrapInvitationByCodeHash(hash string) (*BootstrapInvitation, error) {
	return one(tx, scanInvitation, invByCode, sql.Named("code_hash", hash))
}

// ConsumeBootstrapInvitation marks an invitation used by userID. It succeeds
// once, and only before the invitation expires (ErrNotFound otherwise).
func (tx *TenantTx) ConsumeBootstrapInvitation(id, userID uuid.UUID, at time.Time) error {
	return tx.execOne(invConsume, sql.Named("at", RT(at)), sql.Named("user_id", userID.String()),
		sql.Named("id", id.String()))
}
