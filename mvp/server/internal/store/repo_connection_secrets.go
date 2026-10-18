package store

import (
	"database/sql"
	"errors"
	"time"
)

var (
	connSecretPut = tq("connection_secrets.put", `
		INSERT INTO connection_secrets (tenant_id, secret_ref, sealed, created_at)
		VALUES (@tenant, @secret_ref, @sealed, @now)
		ON CONFLICT (tenant_id, secret_ref) DO UPDATE SET sealed = excluded.sealed, created_at = excluded.created_at`)
	connSecretGet = tq("connection_secrets.get", `
		SELECT s.sealed FROM connection_secrets s WHERE s.tenant_id = @tenant AND s.secret_ref = @secret_ref`)
)

// PutConnectionSecret stores the sealed (never plaintext) credential for a
// "sealed:<id>" reference.
func (tx *TenantTx) PutConnectionSecret(ref string, sealed []byte, now time.Time) error {
	_, err := tx.exec(connSecretPut, sql.Named("secret_ref", ref), sql.Named("sealed", sealed), sql.Named("now", RT(now)))
	return err
}

// ConnectionSecret returns the sealed credential for a reference, or
// ErrNotFound (also for another tenant's reference).
func (tx *TenantTx) ConnectionSecret(ref string) ([]byte, error) {
	var b []byte
	err := tx.queryRow(connSecretGet, sql.Named("secret_ref", ref)).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}
