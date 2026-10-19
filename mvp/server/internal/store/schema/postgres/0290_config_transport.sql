-- Postgres dialect of schema/0211_config_transport.sql (issue #170), kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres. Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE config_signing_keys (
  kid TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  public_key BYTEA NOT NULL CHECK (length(public_key) = 32),
  private_sealed BYTEA NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_config_signing_keys_active ON config_signing_keys (tenant_id) WHERE status = 'active';

CREATE TABLE config_trusted_signers (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kid TEXT NOT NULL,
  public_key BYTEA NOT NULL CHECK (length(public_key) = 32),
  label TEXT NOT NULL,
  added_by TEXT,
  added_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, kid),
  FOREIGN KEY (tenant_id, added_by) REFERENCES platform_users (tenant_id, id)
);

CREATE TABLE config_imports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  bundle_hash TEXT NOT NULL,
  signer_kid TEXT NOT NULL,
  source TEXT NOT NULL,
  exported_at TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '{}',
  applied_by TEXT,
  applied_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, applied_by) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_config_imports_tenant ON config_imports (tenant_id, applied_at);
