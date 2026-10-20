-- Postgres dialect of schema/0360_connector_checkpoints.sql (kept in parity with the SQLite
-- file by TestSchemaParity_SQLiteAndPostgres). cursor and state never hold a credential.

-- +goose Up

CREATE TABLE connector_checkpoints (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  name TEXT NOT NULL,
  cursor TEXT NOT NULL DEFAULT '',
  state BYTEA,
  full_sync_at TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, system, name)
);
