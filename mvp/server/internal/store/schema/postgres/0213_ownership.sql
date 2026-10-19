-- Postgres dialect of schema/0208_ownership.sql (issue #167, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE ownerships (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  object_kind TEXT NOT NULL CHECK (object_kind IN ('app','group','resource','identity')),
  object_key TEXT NOT NULL,
  primary_owner_id BIGINT,
  backup_owner_id BIGINT,
  owner_group_id BIGINT,
  purpose TEXT NOT NULL DEFAULT '',
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  CHECK (primary_owner_id IS NULL OR backup_owner_id IS NULL OR primary_owner_id <> backup_owner_id),
  PRIMARY KEY (tenant_id, object_kind, object_key),
  FOREIGN KEY (tenant_id, primary_owner_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, backup_owner_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_group_id) REFERENCES groups (tenant_id, id),
  FOREIGN KEY (tenant_id, updated_by) REFERENCES platform_users (tenant_id, id)
);

CREATE INDEX ix_ownerships_tenant_primary ON ownerships (tenant_id, primary_owner_id);
CREATE INDEX ix_ownerships_tenant_backup ON ownerships (tenant_id, backup_owner_id);
