-- Deployment readiness: the Directory Agent and its enrolment tokens (DR-11,
-- design docs/design/deployment-readiness.md §5.3).
--
-- Tenant-owned like every table of 0001_tenancy.sql: tenant_id references
-- tenants(id), every UNIQUE constraint starts with tenant_id (except the two
-- bearer hashes below, which GlobalHashLookups allows), and the guard
-- triggers at the end refuse a reference to another tenant's row.
--
-- directory_agents: one row per agent. It is created 'pending' with an
-- enrolment token, becomes 'active' when the agent enrols and presents its
-- client certificate, and 'revoked' by an administrator. cert_pin is the
-- SHA-256 (hex) of the agent certificate's public key (SPKI); Tessera pins
-- that key on the mutual-TLS channel and resolves the agent, and with it the
-- tenant, from it. It is unique across tenants by design (a key identifies
-- one agent), which is why it is a GlobalHashLookups column.
CREATE TABLE IF NOT EXISTS directory_agents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','active','revoked')),
  cert_pin TEXT UNIQUE CHECK (cert_pin IS NULL OR length(cert_pin) = 64),
  hostname TEXT, os TEXT, version TEXT, allowlist_hash TEXT,
  last_seen_at TEXT, enrolled_at TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  revoked_at TEXT, revoked_by TEXT,
  UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS directory_agents_tenant ON directory_agents(tenant_id);

-- agent_enrolments: a single-use enrolment code. Only its SHA-256 (hex) is
-- stored; the code itself is shown once when it is issued. It expires after
-- 15 minutes and is consumed atomically by the enrolment that uses it
-- (consumed_at is set only where it is still NULL and the code is unexpired).
CREATE TABLE IF NOT EXISTS agent_enrolments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  agent_id TEXT NOT NULL REFERENCES directory_agents (id),
  token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_enrolments_tenant ON agent_enrolments(tenant_id, agent_id);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_agent_enrolments_xtenant_ins BEFORE INSERT ON agent_enrolments
WHEN (NEW.agent_id IS NOT NULL AND EXISTS (SELECT 1 FROM directory_agents p WHERE p.id = NEW.agent_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_enrolments'); END;

CREATE TRIGGER IF NOT EXISTS tg_agent_enrolments_xtenant_upd BEFORE UPDATE OF tenant_id, agent_id ON agent_enrolments
WHEN (NEW.agent_id IS NOT NULL AND EXISTS (SELECT 1 FROM directory_agents p WHERE p.id = NEW.agent_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_enrolments'); END;

-- connections.agent_id (0201) now names a directory agent: refuse another
-- tenant's agent.
CREATE TRIGGER IF NOT EXISTS tg_connections_agent_xtenant_ins BEFORE INSERT ON connections
WHEN (NEW.agent_id IS NOT NULL AND EXISTS (SELECT 1 FROM directory_agents p WHERE p.id = NEW.agent_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connections.agent_id'); END;

CREATE TRIGGER IF NOT EXISTS tg_connections_agent_xtenant_upd BEFORE UPDATE OF tenant_id, agent_id ON connections
WHEN (NEW.agent_id IS NOT NULL AND EXISTS (SELECT 1 FROM directory_agents p WHERE p.id = NEW.agent_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connections.agent_id'); END;
