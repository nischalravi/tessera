-- Postgres dialect of schema/0461_agent_jobs.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE agent_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  agent_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('sync')),
  payload TEXT NOT NULL,
  idempotency_key TEXT,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','leased','done','failed','cancelled')),
  attempts BIGINT NOT NULL DEFAULT 0,
  max_attempts BIGINT NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
  lease_expires_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  result_summary TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT,
  UNIQUE (tenant_id, idempotency_key),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES directory_agents (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
CREATE INDEX ix_agent_jobs_claim ON agent_jobs (tenant_id, agent_id, status, lease_expires_at);
CREATE INDEX ix_agent_jobs_connection ON agent_jobs (tenant_id, connection_id, status);
