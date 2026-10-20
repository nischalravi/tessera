-- Postgres dialect of schema/0320_queue.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE queue_schedules (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  spec TEXT NOT NULL,
  enabled BIGINT NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  max_attempts BIGINT NOT NULL DEFAULT 5 CHECK (max_attempts > 0),
  next_run_at TEXT NOT NULL,
  last_enqueued_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id)
);
CREATE INDEX ix_queue_schedules_due ON queue_schedules (tenant_id, enabled, next_run_at);

CREATE TABLE queue_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  idempotency_key TEXT,
  schedule_id TEXT,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','succeeded','failed','dead')),
  run_at TEXT NOT NULL,
  attempts BIGINT NOT NULL DEFAULT 0,
  max_attempts BIGINT NOT NULL DEFAULT 5 CHECK (max_attempts > 0),
  last_error TEXT NOT NULL DEFAULT '',
  lease_owner TEXT,
  lease_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT,
  UNIQUE (tenant_id, kind, idempotency_key),
  FOREIGN KEY (tenant_id, schedule_id) REFERENCES queue_schedules (tenant_id, id)
);
CREATE INDEX ix_queue_jobs_due ON queue_jobs (tenant_id, status, run_at);
CREATE INDEX ix_queue_jobs_lease ON queue_jobs (tenant_id, status, lease_expires_at);
