-- Postgres dialect of schema/0357_mcp_contained.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE mcp_contained (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  contained_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, identity_id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
