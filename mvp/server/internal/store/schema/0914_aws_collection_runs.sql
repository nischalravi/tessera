-- AWS collection runs (issue #637, EP-1; design docs/design/differentiators-plan.md section 1).
--
-- One row per collection of an AWS connector that someone asked for or that
-- changed something: POST /api/aws/connectors/{id}/collect queues a run
-- ('queued', then 'running' while a worker collects and evaluates, then
-- 'succeeded', 'unchanged' or 'failed'); the scheduled collection writes a row
-- only when the estate changed or the run failed, so an unchanged estate
-- writes nothing here. connector_id is not a foreign key, like
-- aws_snapshots.connector_id: the history outlives a deleted connector.
--
-- The partial unique index allows one queued or running run per connector,
-- which is what makes a second POST while a run is active a conflict.
--
-- Tenant-owned like 0001_tenancy.sql: tenant_id on the row, every unique index
-- starts with it, every statement binds it.
CREATE TABLE IF NOT EXISTS aws_collection_runs (
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
  changed INTEGER NOT NULL DEFAULT 0 CHECK (changed IN (0, 1)),
  result TEXT CHECK (result IS NULL OR json_valid(result)),  -- counts only
  error TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS aws_collection_runs_connector ON aws_collection_runs (tenant_id, connector_id, queued_at);
CREATE UNIQUE INDEX IF NOT EXISTS ux_aws_collection_runs_active ON aws_collection_runs (tenant_id, connector_id)
  WHERE status IN ('queued', 'running');
