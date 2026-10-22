-- Per-target limits of the connector workers (issue #302): how hard Tessera may
-- call one connection's system, and when it backs off.
--
-- connection_limits: one optional row per connection. Every value is "0 =
-- use the worker's default" (tessera worker -target-*): max_concurrency is the
-- calls in flight at once per worker process, rate_per_min the calls per
-- minute per worker process (burst is the bucket size; 0 = rate/60, at least
-- 1), breaker_threshold is how many calls in a row must fail before the
-- breaker opens and breaker_cooldown_secs how long it stays open before one
-- probe call is let through. The API validates the ranges; the CHECKs keep a
-- bad write from reaching a worker.
--
-- worker_target_states: what each worker sees of each target it called,
-- written by the worker's heartbeat (internal/worker.Beater), so the breaker
-- state is visible with the worker's health (GET /api/queue/workers). One row
-- per (tenant, worker, connection); a worker replaces its rows on every beat
-- and removes them when it stops. state is closed, open or half_open.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- connection of another tenant.
CREATE TABLE IF NOT EXISTS connection_limits (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  max_concurrency INTEGER NOT NULL DEFAULT 0 CHECK (max_concurrency BETWEEN 0 AND 64),
  rate_per_min INTEGER NOT NULL DEFAULT 0 CHECK (rate_per_min BETWEEN 0 AND 60000),
  burst INTEGER NOT NULL DEFAULT 0 CHECK (burst BETWEEN 0 AND 1000),
  breaker_threshold INTEGER NOT NULL DEFAULT 0 CHECK (breaker_threshold BETWEEN 0 AND 100),
  breaker_cooldown_secs INTEGER NOT NULL DEFAULT 0 CHECK (breaker_cooldown_secs BETWEEN 0 AND 3600),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connection_id)
);

CREATE TRIGGER IF NOT EXISTS tg_connection_limits_xtenant_ins BEFORE INSERT ON connection_limits
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connection_limits'); END;

CREATE TRIGGER IF NOT EXISTS tg_connection_limits_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON connection_limits
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connection_limits'); END;

CREATE TABLE IF NOT EXISTS worker_target_states (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  worker_id TEXT NOT NULL,
  connection_id TEXT NOT NULL REFERENCES connections (id),
  state TEXT NOT NULL CHECK (state IN ('closed','open','half_open')),
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  open_until TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  in_flight INTEGER NOT NULL DEFAULT 0,
  calls INTEGER NOT NULL DEFAULT 0,
  failures INTEGER NOT NULL DEFAULT 0,
  rejected INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, worker_id, connection_id)
);

CREATE TRIGGER IF NOT EXISTS tg_worker_target_states_xtenant_ins BEFORE INSERT ON worker_target_states
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: worker_target_states'); END;

CREATE TRIGGER IF NOT EXISTS tg_worker_target_states_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON worker_target_states
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: worker_target_states'); END;
