-- Postgres dialect of schema/0205_connection_secrets.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE connection_secrets (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  secret_ref TEXT NOT NULL,
  sealed BYTEA NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, secret_ref)
);
