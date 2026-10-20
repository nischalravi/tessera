-- Durable job queue (issue #300): one engine for the background sweepers and
-- the containment retry sweep, safe to run on more than one instance.
--
-- queue_jobs: one row per unit of work. A worker claims a due row by setting
-- lease_owner and lease_expires_at (status running) in one write transaction;
-- a heartbeat extends the lease; a row whose lease expired is claimed again.
-- Statuses: queued (waiting for run_at), running (leased), succeeded, failed
-- (the last attempt failed and a retry is waiting for run_at), dead (attempts
-- exhausted; an operator can retry it). idempotency_key is unique per tenant
-- and kind, so enqueueing the same work twice makes one row.
--
-- queue_schedules: a recurring job as a row. When next_run_at passes, one
-- worker enqueues the job (idempotency key schedule:name:due time) and moves
-- next_run_at on, in one transaction. spec is "@every 30s" or a 5-field cron.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- job that points at another tenant's schedule.
CREATE TABLE IF NOT EXISTS queue_schedules (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  spec TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  max_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts > 0),
  next_run_at TEXT NOT NULL,
  last_enqueued_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS ix_queue_schedules_due ON queue_schedules (tenant_id, enabled, next_run_at);

CREATE TABLE IF NOT EXISTS queue_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  idempotency_key TEXT,
  schedule_id TEXT REFERENCES queue_schedules (id),
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','succeeded','failed','dead')),
  run_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts > 0),
  last_error TEXT NOT NULL DEFAULT '',
  lease_owner TEXT,
  lease_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT,
  UNIQUE (tenant_id, kind, idempotency_key)
);
CREATE INDEX IF NOT EXISTS ix_queue_jobs_due ON queue_jobs (tenant_id, status, run_at);
CREATE INDEX IF NOT EXISTS ix_queue_jobs_lease ON queue_jobs (tenant_id, status, lease_expires_at);

CREATE TRIGGER IF NOT EXISTS tg_queue_jobs_xtenant_ins BEFORE INSERT ON queue_jobs
WHEN NEW.schedule_id IS NOT NULL AND EXISTS (SELECT 1 FROM queue_schedules p WHERE p.id = NEW.schedule_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: queue_jobs'); END;

CREATE TRIGGER IF NOT EXISTS tg_queue_jobs_xtenant_upd BEFORE UPDATE OF tenant_id, schedule_id ON queue_jobs
WHEN NEW.schedule_id IS NOT NULL AND EXISTS (SELECT 1 FROM queue_schedules p WHERE p.id = NEW.schedule_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: queue_jobs'); END;
