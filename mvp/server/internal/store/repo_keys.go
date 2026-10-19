package store

import (
	"database/sql"
	"errors"
	"time"
)

// Signing keys. Tenant keys are reached only through *TenantTx (tq
// statements); platform keys only through *SystemTx (sq statements). Status
// changes are compare-and-set on the expected current status.

const signingKeyCols = `k.kid, k.tenant_id, k.purpose, k.alg, k.public_jwk, k.private_key_enc, k.status, k.created_at,
	k.activated_at, k.retired_at`

var (
	signingKeysInsert = tq("signing_keys.insert", `
		INSERT INTO tenant_signing_keys (kid, tenant_id, purpose, alg, public_jwk, private_key_enc, status, created_at,
			activated_at)
		VALUES (@kid, @tenant, @purpose, @alg, @public_jwk, @private_key_enc, @status, @created_at, @activated_at)`)
	signingKeysByPurpose = tq("signing_keys.by_purpose", `
		SELECT `+signingKeyCols+` FROM tenant_signing_keys k
		WHERE k.tenant_id = @tenant AND k.purpose = @purpose ORDER BY k.created_at, k.rowid`)
	signingKeysGet = tq("signing_keys.get", `
		SELECT `+signingKeyCols+` FROM tenant_signing_keys k WHERE k.tenant_id = @tenant AND k.kid = @kid`)
	signingKeysActivate = tq("signing_keys.activate", `
		UPDATE tenant_signing_keys SET status = 'active', activated_at = @now
		WHERE tenant_id = @tenant AND kid = @kid AND status = 'next'`)
	signingKeysRetire = tq("signing_keys.retire", `
		UPDATE tenant_signing_keys SET status = 'retired', retired_at = @now
		WHERE tenant_id = @tenant AND kid = @kid AND status = 'active'`)
	signingKeysRevoke = tq("signing_keys.revoke", `
		UPDATE tenant_signing_keys SET status = 'revoked', retired_at = COALESCE(retired_at, @now)
		WHERE tenant_id = @tenant AND kid = @kid AND status IN ('next', 'active', 'retired')`)
)

func scanSigningKey(s scanner) (*TenantSigningKey, error) {
	var k TenantSigningKey
	var tid, jwk, created string
	var activated, retired sql.NullString
	if err := s.Scan(&k.KID, &tid, &k.Purpose, &k.Alg, &jwk, &k.PrivateKeyEnc, &k.Status, &created,
		&activated, &retired); err != nil {
		return nil, err
	}
	var err error
	if k.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	k.PublicJWK = []byte(jwk)
	if k.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if k.ActivatedAt, err = rtp(activated); err != nil {
		return nil, err
	}
	k.RetiredAt, err = rtp(retired)
	return &k, err
}

// InsertSigningKey adds a key with status next or active (ErrDuplicate if
// the kid exists or the tenant already has a key of that status and purpose).
func (tx *TenantTx) InsertSigningKey(k *TenantSigningKey) error {
	if err := tx.own(k.TenantID); err != nil {
		return err
	}
	if k.Status != KeyNext && k.Status != KeyActive {
		return errors.New("store: a new signing key must be next or active")
	}
	_, err := tx.exec(signingKeysInsert, sql.Named("kid", k.KID), sql.Named("purpose", k.Purpose),
		sql.Named("alg", k.Alg), sql.Named("public_jwk", string(k.PublicJWK)),
		sql.Named("private_key_enc", k.PrivateKeyEnc), sql.Named("status", k.Status),
		sql.Named("created_at", RT(k.CreatedAt)), sql.Named("activated_at", RTP(k.ActivatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// SigningKeys lists this tenant's keys for purpose (every status) in creation order.
func (tx *TenantTx) SigningKeys(purpose string) ([]*TenantSigningKey, error) {
	return collect(tx, scanSigningKey, signingKeysByPurpose, sql.Named("purpose", purpose))
}

// SigningKey returns one of this tenant's keys (ErrNotFound otherwise,
// including for another tenant's kid).
func (tx *TenantTx) SigningKey(kid string) (*TenantSigningKey, error) {
	return one(tx, scanSigningKey, signingKeysGet, sql.Named("kid", kid))
}

func (tx *TenantTx) keyTransition(st tstmt, kid string, now time.Time) error {
	res, err := tx.exec(st, sql.Named("kid", kid), sql.Named("now", RT(now)))
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// ActivateSigningKey moves a next key to active (ErrNotFound unless kid is
// this tenant's next key; ErrDuplicate while another key is active).
func (tx *TenantTx) ActivateSigningKey(kid string, now time.Time) error {
	return tx.keyTransition(signingKeysActivate, kid, now)
}

// RetireSigningKey moves an active key to retired.
func (tx *TenantTx) RetireSigningKey(kid string, now time.Time) error {
	return tx.keyTransition(signingKeysRetire, kid, now)
}

// RevokeSigningKey marks a next, active or retired key revoked.
func (tx *TenantTx) RevokeSigningKey(kid string, now time.Time) error {
	return tx.keyTransition(signingKeysRevoke, kid, now)
}

// ---------------------------------------------------------------- platform keys (GLOBAL)

const platformKeyCols = `p.kid, p.purpose, p.alg, p.public_jwk, p.private_key_enc, p.status, p.created_at`

var (
	platformKeysInsert = sq("platform_keys.insert", `
		INSERT INTO platform_keys (kid, purpose, alg, public_jwk, private_key_enc, status, created_at)
		VALUES (@kid, @purpose, @alg, @public_jwk, @private_key_enc, 'active', @created_at)`)
	platformKeysByPurpose = sq("platform_keys.by_purpose", `
		SELECT `+platformKeyCols+` FROM platform_keys p WHERE p.purpose = @purpose ORDER BY p.created_at, p.rowid`)
	platformKeysRetire = sq("platform_keys.retire", `
		UPDATE platform_keys SET status = 'retired' WHERE kid = @kid AND status = 'active'`)
	platformKeysRevoke = sq("platform_keys.revoke", `
		UPDATE platform_keys SET status = 'revoked' WHERE kid = @kid AND status IN ('active', 'retired')`)
)

// RevokePlatformKey marks an active or retired platform key revoked (an
// emergency: it is never published again, so checkpoints it signed no
// longer verify). ErrNotFound for an unknown or already revoked kid.
func (s *SystemTx) RevokePlatformKey(kid string) error {
	res, err := s.exec(platformKeysRevoke, sql.Named("kid", kid))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

// InsertPlatformKey adds an active platform key (ErrDuplicate if one is
// already active for the purpose).
func (s *SystemTx) InsertPlatformKey(k PlatformKey) error {
	_, err := s.exec(platformKeysInsert, sql.Named("kid", k.KID), sql.Named("purpose", k.Purpose),
		sql.Named("alg", k.Alg), sql.Named("public_jwk", string(k.PublicJWK)),
		sql.Named("private_key_enc", k.PrivateKeyEnc), sql.Named("created_at", RT(k.CreatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// PlatformKeys lists the platform keys for purpose (every status), oldest first.
func (s *SystemTx) PlatformKeys(purpose string) (out []PlatformKey, err error) {
	rows, err := s.query(platformKeysByPurpose, sql.Named("purpose", purpose))
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
	}()
	for rows.Next() {
		var k PlatformKey
		var jwk, created string
		if err := rows.Scan(&k.KID, &k.Purpose, &k.Alg, &jwk, &k.PrivateKeyEnc, &k.Status, &created); err != nil {
			return nil, err
		}
		k.PublicJWK = []byte(jwk)
		if k.CreatedAt, err = ParseRT(created); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RetirePlatformKey moves an active platform key to retired.
func (s *SystemTx) RetirePlatformKey(kid string) error {
	res, err := s.exec(platformKeysRetire, sql.Named("kid", kid))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}
