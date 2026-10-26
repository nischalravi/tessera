-- Postgres dialect of schema/0914_aws_collection_runs.sql (issue #637, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). connector_id is deliberately not a foreign key (the history
-- outlives a deleted connector); see 0001_tenancy.sql for the tenant rules.

-- +goose Up

CREATE TABLE aws_collection_runs (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  trigger TEXT NOT NULL CHECK (trigger IN ('manual', 'schedule')),
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'unchanged', 'failed')),
  requested_by TEXT NOT NULL,
  queued_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  snapshot_id TEXT,
  changed BIGINT NOT NULL DEFAULT 0 CHECK (changed IN (0, 1)),
  result TEXT CHECK (result IS NULL OR result IS JSON),
  error TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX aws_collection_runs_connector ON aws_collection_runs (tenant_id, connector_id, queued_at);
CREATE UNIQUE INDEX ux_aws_collection_runs_active ON aws_collection_runs (tenant_id, connector_id)
  WHERE status IN ('queued', 'running');
