-- Postgres dialect of schema/0460_queue_workers.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE queue_workers (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  worker_id TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('worker','api')),
  hostname TEXT NOT NULL DEFAULT '',
  pid BIGINT NOT NULL DEFAULT 0,
  version TEXT NOT NULL DEFAULT '',
  kinds TEXT NOT NULL DEFAULT '',
  concurrency BIGINT NOT NULL DEFAULT 0,
  running BIGINT NOT NULL DEFAULT 0,
  started_at TEXT NOT NULL,
  last_heartbeat_at TEXT NOT NULL,
  UNIQUE (tenant_id, worker_id),
  UNIQUE (tenant_id, id)
);
CREATE INDEX ix_queue_workers_beat ON queue_workers (tenant_id, last_heartbeat_at);
