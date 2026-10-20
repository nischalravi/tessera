-- Connector worker pool (issue #302): the health of the `tessera worker`
-- processes (and of an API process that runs queue kinds in-process).
--
-- queue_workers: one row per (tenant, worker). A worker serves every tenant,
-- so each beat writes one row per active tenant: the table stays tenant-owned
-- (every query is scoped, RLS applies) at the cost of tenants x workers rows.
-- worker_id is the queue's lease owner (host-pid-random), so a stuck lease in
-- queue_jobs.lease_owner can be matched with the worker that held it.
-- kinds is the comma-separated list of kinds the worker claims. Rows whose
-- last beat is older than a day are deleted by the next beat of any worker.
--
-- Tenant-owned like 0001_tenancy.sql; there is no reference to guard.
CREATE TABLE IF NOT EXISTS queue_workers (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  worker_id TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('worker','api')),
  hostname TEXT NOT NULL DEFAULT '',
  pid INTEGER NOT NULL DEFAULT 0,
  version TEXT NOT NULL DEFAULT '',
  kinds TEXT NOT NULL DEFAULT '',
  concurrency INTEGER NOT NULL DEFAULT 0,
  running INTEGER NOT NULL DEFAULT 0,
  started_at TEXT NOT NULL,
  last_heartbeat_at TEXT NOT NULL,
  UNIQUE (tenant_id, worker_id)
);
CREATE INDEX IF NOT EXISTS ix_queue_workers_beat ON queue_workers (tenant_id, last_heartbeat_at);
