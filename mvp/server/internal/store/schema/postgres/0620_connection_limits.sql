-- Postgres dialect of schema/0620_connection_limits.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE connection_limits (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL,
  max_concurrency BIGINT NOT NULL DEFAULT 0 CHECK (max_concurrency BETWEEN 0 AND 64),
  rate_per_min BIGINT NOT NULL DEFAULT 0 CHECK (rate_per_min BETWEEN 0 AND 60000),
  burst BIGINT NOT NULL DEFAULT 0 CHECK (burst BETWEEN 0 AND 1000),
  breaker_threshold BIGINT NOT NULL DEFAULT 0 CHECK (breaker_threshold BETWEEN 0 AND 100),
  breaker_cooldown_secs BIGINT NOT NULL DEFAULT 0 CHECK (breaker_cooldown_secs BETWEEN 0 AND 3600),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connection_id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);

CREATE TABLE worker_target_states (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  worker_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('closed','open','half_open')),
  consecutive_failures BIGINT NOT NULL DEFAULT 0,
  open_until TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  in_flight BIGINT NOT NULL DEFAULT 0,
  calls BIGINT NOT NULL DEFAULT 0,
  failures BIGINT NOT NULL DEFAULT 0,
  rejected BIGINT NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, worker_id, connection_id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
