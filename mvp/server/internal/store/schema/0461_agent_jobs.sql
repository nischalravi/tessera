-- Remote private-network agents that pull jobs (issue #302).
--
-- agent_jobs: one unit of work for one Directory Agent about one connection.
-- Tessera never dials in: a worker (or the API) writes a row, the agent
-- long-polls over mutual TLS, claims the rows addressed to its own id, runs
-- them in its network and posts the typed result, which the API records
-- through the normal ingest path in the same transaction that finishes the row.
--
-- The addressing is the whole access control: a claim and a result are always
-- scoped to the (tenant, agent) of the pinned client key, never to anything the
-- agent sends. A row names the connection it is for, so an agent only ever
-- sees jobs for connections bound to it (the connection's active revision
-- holds an agent:<id>/<name> credential reference).
--
-- Statuses: queued (waiting), leased (an agent holds it until lease_expires_at;
-- an expired lease is claimed again), done, failed (attempts exhausted or a
-- permanent error), cancelled (the agent was revoked). payload is the typed
-- job (target and non-secret connection settings, never a credential: the
-- secret stays in the agent's own store). result_summary is counts only.
-- idempotency_key is unique per tenant, so enqueueing the same work twice
-- makes one row.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse an
-- agent or connection of another tenant.
CREATE TABLE IF NOT EXISTS agent_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  agent_id TEXT NOT NULL REFERENCES directory_agents (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  kind TEXT NOT NULL CHECK (kind IN ('sync')),
  payload TEXT NOT NULL,
  idempotency_key TEXT,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','leased','done','failed','cancelled')),
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
  lease_expires_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  result_summary TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT,
  UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS ix_agent_jobs_claim ON agent_jobs (tenant_id, agent_id, status, lease_expires_at);
CREATE INDEX IF NOT EXISTS ix_agent_jobs_connection ON agent_jobs (tenant_id, connection_id, status);

CREATE TRIGGER IF NOT EXISTS tg_agent_jobs_xtenant_ins BEFORE INSERT ON agent_jobs
WHEN (EXISTS (SELECT 1 FROM directory_agents p WHERE p.id = NEW.agent_id AND p.tenant_id <> NEW.tenant_id))
	OR (EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_jobs'); END;

CREATE TRIGGER IF NOT EXISTS tg_agent_jobs_xtenant_upd BEFORE UPDATE OF tenant_id, agent_id, connection_id ON agent_jobs
WHEN (EXISTS (SELECT 1 FROM directory_agents p WHERE p.id = NEW.agent_id AND p.tenant_id <> NEW.tenant_id))
	OR (EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_jobs'); END;
