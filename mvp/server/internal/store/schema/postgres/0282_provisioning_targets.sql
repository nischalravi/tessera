-- Postgres dialect of schema/0282_provisioning_targets.sql (kept in parity with the SQLite
-- file by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE provisioning_targets (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('scim','okta','fake','cyberark','delinea','beyondtrust','sap','oracle','rest','sql','salesforce','ldap','ad')),
  base_url TEXT NOT NULL,
  settings TEXT NOT NULL DEFAULT '{}',
  credential_enc BYTEA,
  credential_version TEXT,
  write_back BIGINT NOT NULL DEFAULT 0 CHECK (write_back IN (0,1)),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connection_id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
CREATE INDEX provisioning_targets_tenant ON provisioning_targets (tenant_id);
