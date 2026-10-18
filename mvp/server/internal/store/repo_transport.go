package store

import (
	"database/sql"
	"time"
)

// Configuration transport (schema/0211_config_transport.sql, issue #170).

// ConfigSigningKey is a tenant's bundle signing key.
type ConfigSigningKey struct {
	KID           string
	PublicKey     []byte // Ed25519, 32 bytes
	PrivateSealed []byte
	Status        string // active | retired
	CreatedAt     time.Time
}

// TrustedSigner is a bundle signer a tenant accepts imports from.
type TrustedSigner struct {
	KID       string
	PublicKey []byte
	Label     string
	AddedBy   *string
	AddedAt   time.Time
}

// ConfigImport is one applied bundle.
type ConfigImport struct {
	ID         string
	BundleHash string
	SignerKID  string
	Source     string
	ExportedAt time.Time
	Summary    string // JSON counts
	AppliedBy  *string
	AppliedAt  time.Time
}

var (
	configKeyActive = tq("config_signing_keys.active", `
		SELECT k.kid, k.public_key, k.private_sealed, k.status, k.created_at FROM config_signing_keys k
		WHERE k.tenant_id = @tenant AND k.status = 'active'`)
	configKeyInsert = tq("config_signing_keys.insert", `
		INSERT INTO config_signing_keys (kid, tenant_id, public_key, private_sealed, status, created_at)
		VALUES (@kid, @tenant, @public_key, @private_sealed, 'active', @created_at)`)
	trustedSignersList = tq("config_trusted_signers.list", `
		SELECT s.kid, s.public_key, s.label, s.added_by, s.added_at FROM config_trusted_signers s
		WHERE s.tenant_id = @tenant ORDER BY s.label, s.kid`)
	trustedSignerGet = tq("config_trusted_signers.get", `
		SELECT s.kid, s.public_key, s.label, s.added_by, s.added_at FROM config_trusted_signers s
		WHERE s.tenant_id = @tenant AND s.kid = @kid`)
	trustedSignerInsert = tq("config_trusted_signers.insert", `
		INSERT INTO config_trusted_signers (tenant_id, kid, public_key, label, added_by, added_at)
		VALUES (@tenant, @kid, @public_key, @label, @added_by, @added_at)`)
	trustedSignerDelete = tq("config_trusted_signers.delete", `
		DELETE FROM config_trusted_signers WHERE tenant_id = @tenant AND kid = @kid`)
	configImportInsert = tq("config_imports.insert", `
		INSERT INTO config_imports (id, tenant_id, bundle_hash, signer_kid, source, exported_at, summary, applied_by, applied_at)
		VALUES (@id, @tenant, @bundle_hash, @signer_kid, @source, @exported_at, @summary, @applied_by, @applied_at)`)
	configImportsList = tq("config_imports.list", `
		SELECT i.id, i.bundle_hash, i.signer_kid, i.source, i.exported_at, i.summary, i.applied_by, i.applied_at
		FROM config_imports i WHERE i.tenant_id = @tenant ORDER BY i.applied_at DESC, i.id LIMIT 50`)
)

// ActiveConfigSigningKey returns the tenant's active bundle signing key, or ErrNotFound.
func (tx *TenantTx) ActiveConfigSigningKey() (*ConfigSigningKey, error) {
	return one(tx, func(s scanner) (*ConfigSigningKey, error) {
		var k ConfigSigningKey
		var at nullTime
		if err := s.Scan(&k.KID, &k.PublicKey, &k.PrivateSealed, &k.Status, &at); err != nil {
			return nil, err
		}
		var err error
		k.CreatedAt, err = at.val()
		return &k, err
	}, configKeyActive)
}

// InsertConfigSigningKey stores a new active signing key.
func (tx *TenantTx) InsertConfigSigningKey(k *ConfigSigningKey) error {
	_, err := tx.exec(configKeyInsert, sql.Named("kid", k.KID), sql.Named("public_key", k.PublicKey),
		sql.Named("private_sealed", k.PrivateSealed), sql.Named("created_at", T(k.CreatedAt)))
	return err
}

func scanTrustedSigner(s scanner) (*TrustedSigner, error) {
	var t TrustedSigner
	var by sql.NullString
	var at nullTime
	if err := s.Scan(&t.KID, &t.PublicKey, &t.Label, &by, &at); err != nil {
		return nil, err
	}
	t.AddedBy = strp(by)
	var err error
	t.AddedAt, err = at.val()
	return &t, err
}

// TrustedSigners lists the signers the tenant imports from.
func (tx *TenantTx) TrustedSigners() ([]*TrustedSigner, error) {
	return collect(tx, scanTrustedSigner, trustedSignersList)
}

// TrustedSigner returns one trusted signer, or ErrNotFound.
func (tx *TenantTx) TrustedSigner(kid string) (*TrustedSigner, error) {
	return one(tx, scanTrustedSigner, trustedSignerGet, sql.Named("kid", kid))
}

// InsertTrustedSigner trusts a signer.
func (tx *TenantTx) InsertTrustedSigner(t *TrustedSigner) error {
	_, err := tx.exec(trustedSignerInsert, sql.Named("kid", t.KID), sql.Named("public_key", t.PublicKey), sql.Named("label", t.Label),
		sql.Named("added_by", SP(t.AddedBy)), sql.Named("added_at", T(t.AddedAt)))
	return err
}

// DeleteTrustedSigner stops trusting a signer (ErrNotFound if it was not trusted).
func (tx *TenantTx) DeleteTrustedSigner(kid string) error {
	return tx.execOne(trustedSignerDelete, sql.Named("kid", kid))
}

// InsertConfigImport records an applied bundle.
func (tx *TenantTx) InsertConfigImport(i *ConfigImport) error {
	_, err := tx.exec(configImportInsert, sql.Named("id", i.ID), sql.Named("bundle_hash", i.BundleHash),
		sql.Named("signer_kid", i.SignerKID), sql.Named("source", i.Source), sql.Named("exported_at", T(i.ExportedAt)),
		sql.Named("summary", i.Summary), sql.Named("applied_by", SP(i.AppliedBy)), sql.Named("applied_at", T(i.AppliedAt)))
	return err
}

// ConfigImports lists the latest applied bundles.
func (tx *TenantTx) ConfigImports() ([]*ConfigImport, error) {
	return collect(tx, func(s scanner) (*ConfigImport, error) {
		var i ConfigImport
		var by sql.NullString
		var exp, at nullTime
		if err := s.Scan(&i.ID, &i.BundleHash, &i.SignerKID, &i.Source, &exp, &i.Summary, &by, &at); err != nil {
			return nil, err
		}
		i.AppliedBy = strp(by)
		var err error
		if i.ExportedAt, err = exp.val(); err != nil {
			return nil, err
		}
		i.AppliedAt, err = at.val()
		return &i, err
	}, configImportsList)
}
