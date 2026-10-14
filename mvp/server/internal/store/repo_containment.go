package store

import (
	"database/sql"
	"time"
)

// Identity containment credentials (schema/0205_containment.sql). The token
// is sealed by internal/containment; the store only holds the sealed bytes.

// ContainmentCredential is the sealed provider credential of one connection.
type ContainmentCredential struct {
	ConnectionID string
	BaseURL      string
	Org          string
	TokenEnc     []byte
	UpdatedBy    string
	UpdatedAt    time.Time
}

const containmentCols = `k.connection_id, k.base_url, k.org, k.token_enc, k.updated_by, k.updated_at`

var (
	containmentPut = tq("containment_credentials.put", `
		INSERT INTO containment_credentials (tenant_id, connection_id, base_url, org, token_enc, updated_by, updated_at)
		VALUES (@tenant, @connection_id, @base_url, @org, @token_enc, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, connection_id) DO UPDATE SET base_url = excluded.base_url, org = excluded.org,
			token_enc = excluded.token_enc, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	containmentGet = tq("containment_credentials.get", `
		SELECT `+containmentCols+` FROM containment_credentials k
		WHERE k.tenant_id = @tenant AND k.connection_id = @connection_id`)
	containmentList = tq("containment_credentials.list", `
		SELECT `+containmentCols+` FROM containment_credentials k WHERE k.tenant_id = @tenant ORDER BY k.connection_id`)
)

func scanContainmentCredential(s scanner) (*ContainmentCredential, error) {
	var k ContainmentCredential
	var at string
	if err := s.Scan(&k.ConnectionID, &k.BaseURL, &k.Org, &k.TokenEnc, &k.UpdatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	k.UpdatedAt, err = ParseRT(at)
	return &k, err
}

// PutContainmentCredential stores (or replaces) a connection's sealed credential.
func (tx *TenantTx) PutContainmentCredential(k *ContainmentCredential) error {
	_, err := tx.exec(containmentPut, sql.Named("connection_id", k.ConnectionID), sql.Named("base_url", k.BaseURL),
		sql.Named("org", k.Org), sql.Named("token_enc", k.TokenEnc), sql.Named("updated_by", k.UpdatedBy),
		sql.Named("updated_at", RT(k.UpdatedAt)))
	return err
}

// ContainmentCredential returns a connection's credential or ErrNotFound.
func (tx *TenantTx) ContainmentCredential(connectionID string) (*ContainmentCredential, error) {
	return one(tx, scanContainmentCredential, containmentGet, sql.Named("connection_id", connectionID))
}

// ContainmentCredentials lists the tenant's credentials.
func (tx *TenantTx) ContainmentCredentials() ([]*ContainmentCredential, error) {
	return collect(tx, scanContainmentCredential, containmentList)
}
