-- Postgres dialect of schema/0410_certificates.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The cross-tenant guard triggers become composite foreign keys
-- (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql. key_sealed is BYTEA and json_valid is IS JSON.

-- +goose Up

CREATE TABLE tenant_certificates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  purpose TEXT NOT NULL CHECK (purpose IN ('saml_sp','mtls_client','signing','encryption')),
  label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
  idp_connection_id TEXT,
  connection_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('next','active','retired')),
  cert_pem TEXT NOT NULL,
  key_sealed BYTEA,
  subject TEXT NOT NULL,
  issuer TEXT NOT NULL,
  sans TEXT NOT NULL DEFAULT '[]' CHECK (sans IS JSON),
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
  key_algorithm TEXT NOT NULL,
  sig_algorithm TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  activated_at TEXT,
  retired_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, purpose, fingerprint),
  CHECK ((purpose = 'saml_sp') = (idp_connection_id IS NOT NULL)),
  CHECK (purpose = 'mtls_client' OR connection_id IS NULL),
  CHECK (status <> 'retired' OR key_sealed IS NULL),
  FOREIGN KEY (tenant_id, idp_connection_id) REFERENCES idp_connections (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
CREATE INDEX tenant_certificates_tenant ON tenant_certificates(tenant_id, purpose, status);
-- at most one certificate waiting to be promoted per SAML connection
CREATE UNIQUE INDEX tenant_certificates_one_next ON tenant_certificates(tenant_id, idp_connection_id) WHERE status = 'next';
