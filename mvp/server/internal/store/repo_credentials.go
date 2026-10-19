package store

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Sealed connection credentials (schema/0345_connection_credentials.sql). The
// secret is sealed by the caller (internal/readiness, internal/containment)
// under CredentialAAD; the store only holds the sealed bytes.

// Credential purposes.
const (
	PurposeBind        = "bind"        // a readiness revision's live-check credential (ref "sealed:<id>")
	PurposeContainment = "containment" // the kill-switch provider token (ref "")
)

// CredentialTable and CredentialColumn name the sealed column in the AAD.
const (
	CredentialTable  = "connection_credentials"
	CredentialColumn = "sealed"
)

// CredentialAAD is the AAD every sealed credential is bound to: tenant, table,
// column, connection, purpose and (when non-empty) ref. Sealing and opening
// both go through it, so a blob copied to another connection, purpose, ref or
// tenant does not open.
func CredentialAAD(tenant tenancy.ID, connectionID, purpose, ref string) []byte {
	row := []string{connectionID, purpose}
	if ref != "" {
		row = append(row, ref)
	}
	return seal.AAD(tenant, CredentialTable, CredentialColumn, row...)
}

// Credential is one sealed secret of a connection, with its plain settings.
type Credential struct {
	ConnectionID string
	Purpose      string
	Ref          string
	Sealed       []byte
	BaseURL      string
	Org          string
	UpdatedBy    string
	UpdatedAt    time.Time
}

const credentialCols = `k.connection_id, k.purpose, k.ref, k.sealed, k.base_url, k.org, k.updated_by, k.updated_at`

var (
	credentialPut = tq("connection_credentials.put", `
		INSERT INTO connection_credentials (tenant_id, connection_id, purpose, ref, sealed, base_url, org, updated_by, updated_at)
		VALUES (@tenant, @connection_id, @purpose, @ref, @sealed, @base_url, @org, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, connection_id, purpose, ref) DO UPDATE SET sealed = excluded.sealed,
			base_url = excluded.base_url, org = excluded.org, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	credentialGet = tq("connection_credentials.get", `
		SELECT `+credentialCols+` FROM connection_credentials k
		WHERE k.tenant_id = @tenant AND k.connection_id = @connection_id AND k.purpose = @purpose AND k.ref = @ref`)
	credentialList = tq("connection_credentials.list", `
		SELECT `+credentialCols+` FROM connection_credentials k
		WHERE k.tenant_id = @tenant AND k.purpose = @purpose ORDER BY k.connection_id, k.ref`)
	credentialDelete = tq("connection_credentials.delete", `
		DELETE FROM connection_credentials
		WHERE tenant_id = @tenant AND connection_id = @connection_id AND purpose = @purpose AND ref = @ref`)
)

func scanCredential(s scanner) (*Credential, error) {
	var k Credential
	var at string
	if err := s.Scan(&k.ConnectionID, &k.Purpose, &k.Ref, &k.Sealed, &k.BaseURL, &k.Org, &k.UpdatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	k.UpdatedAt, err = ParseRT(at)
	return &k, err
}

// PutCredential stores (or replaces) a connection's sealed credential.
func (tx *TenantTx) PutCredential(k *Credential) error {
	_, err := tx.exec(credentialPut, sql.Named("connection_id", k.ConnectionID), sql.Named("purpose", k.Purpose),
		sql.Named("ref", k.Ref), sql.Named("sealed", k.Sealed), sql.Named("base_url", k.BaseURL), sql.Named("org", k.Org),
		sql.Named("updated_by", k.UpdatedBy), sql.Named("updated_at", RT(k.UpdatedAt)))
	return err
}

// Credential returns one credential or ErrNotFound (also for another tenant's connection).
func (tx *TenantTx) Credential(connectionID, purpose, ref string) (*Credential, error) {
	return one(tx, scanCredential, credentialGet, sql.Named("connection_id", connectionID),
		sql.Named("purpose", purpose), sql.Named("ref", ref))
}

// Credentials lists the tenant's credentials of one purpose.
func (tx *TenantTx) Credentials(purpose string) ([]*Credential, error) {
	return collect(tx, scanCredential, credentialList, sql.Named("purpose", purpose))
}

// DeleteCredential removes one credential (ErrNotFound when there is none).
func (tx *TenantTx) DeleteCredential(connectionID, purpose, ref string) error {
	return tx.execOne(credentialDelete, sql.Named("connection_id", connectionID), sql.Named("purpose", purpose),
		sql.Named("ref", ref))
}
