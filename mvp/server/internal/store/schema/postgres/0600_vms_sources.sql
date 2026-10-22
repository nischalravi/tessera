-- Postgres dialect of schema/0600_vms_sources.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres).

-- +goose Up

CREATE TABLE vms_sources (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  vendor TEXT NOT NULL CHECK (vendor IN ('fieldglass','beeline','csv')),
  name TEXT NOT NULL CHECK (name <> ''),
  base_url TEXT NOT NULL DEFAULT '',
  settings TEXT NOT NULL DEFAULT '{}',
  credential_enc BYTEA,
  credential_version TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused')),
  cursor TEXT,
  last_sync_at TEXT,
  last_result TEXT CHECK (last_result IN ('ok','failed')),
  last_error TEXT,
  last_counts TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);
CREATE INDEX ix_vms_sources_tenant ON vms_sources (tenant_id, status);
