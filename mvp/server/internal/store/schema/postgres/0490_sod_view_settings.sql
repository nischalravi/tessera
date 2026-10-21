-- Postgres dialect of schema/0490_sod_view_settings.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The table references no other tenant-owned row;
-- json_valid is IS JSON.

-- +goose Up

CREATE TABLE sod_view_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  visible_columns TEXT NOT NULL CHECK (visible_columns IS JSON),
  visible_filters TEXT NOT NULL CHECK (visible_filters IS JSON),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
