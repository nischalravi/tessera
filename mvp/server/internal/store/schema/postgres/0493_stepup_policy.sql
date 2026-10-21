-- Postgres dialect of schema/0493_stepup_policy.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The table references no other tenant-owned row;
-- json_valid is IS JSON.

-- +goose Up

CREATE TABLE stepup_policy (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  entries TEXT NOT NULL CHECK (entries IS JSON),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
