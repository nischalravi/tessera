-- Postgres dialect of schema/0380_request_settings.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The table references no other tenant-owned row.

-- +goose Up

CREATE TABLE request_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  justification_required BIGINT NOT NULL DEFAULT 1 CHECK (justification_required IN (0, 1)),
  justification_min_length BIGINT NOT NULL DEFAULT 1 CHECK (justification_min_length BETWEEN 1 AND 1000),
  default_hours DOUBLE PRECISION CHECK (default_hours IS NULL OR default_hours > 0),
  max_hours DOUBLE PRECISION CHECK (max_hours IS NULL OR max_hours > 0),
  attachments_allowed BIGINT NOT NULL DEFAULT 0 CHECK (attachments_allowed IN (0, 1)),
  history_visibility TEXT NOT NULL DEFAULT 'readers' CHECK (history_visibility IN ('involved','readers')),
  for_others TEXT NOT NULL DEFAULT 'permission' CHECK (for_others IN ('nobody','managers','permission')),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
