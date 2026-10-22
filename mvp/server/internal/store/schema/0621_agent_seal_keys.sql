-- The public key a Directory Agent holds a secret under (issue #302).
--
-- A pulled provisioning push (agent_jobs.kind = 'provision_push') carries the
-- target's server-held credential to the agent, sealed to this key when the
-- job is claimed (internal/seal: SealToAgent, X25519 + HKDF + AES-GCM, bound
-- to tenant, agent, connection and job). The agent generates the key pair and
-- registers the public half over its mutual-TLS channel (POST
-- /agent/v1/seal-key), so the key is authentic by the same pin that
-- authenticates every other request; the private half never leaves the agent.
-- One key per agent: registering again replaces it (a key rotation, audited
-- agent.seal_key_registered). key_id is the first 16 hex digits of the key's
-- SHA-256, for the audit trail and the admin view. The key is public: it is
-- not sealed under the KEK.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse an
-- agent of another tenant.
CREATE TABLE IF NOT EXISTS agent_seal_keys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  agent_id TEXT NOT NULL REFERENCES directory_agents (id),
  public_key BLOB NOT NULL CHECK (length(public_key) = 32),
  key_id TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  UNIQUE (tenant_id, agent_id)
);

CREATE TRIGGER IF NOT EXISTS tg_agent_seal_keys_xtenant_ins BEFORE INSERT ON agent_seal_keys
WHEN EXISTS (SELECT 1 FROM directory_agents p WHERE p.id = NEW.agent_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_seal_keys'); END;

CREATE TRIGGER IF NOT EXISTS tg_agent_seal_keys_xtenant_upd BEFORE UPDATE OF tenant_id, agent_id ON agent_seal_keys
WHEN EXISTS (SELECT 1 FROM directory_agents p WHERE p.id = NEW.agent_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_seal_keys'); END;
