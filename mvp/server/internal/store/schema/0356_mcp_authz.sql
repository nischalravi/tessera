-- MCP authorization server (issue #115): resource servers, CIMD clients,
-- authorization requests and codes, issued tokens, the decision log and the
-- actor-assertion replay guard.
--
-- Every table is tenant-owned like 0001_tenancy.sql: the guard triggers at the
-- end refuse a reference to another tenant's identity. Secrets are never
-- stored in clear: resource secrets and authorization codes are SHA-256 hashes
-- of high-entropy random values (verify-only); access tokens are signed JWTs
-- (internal/keys) and only their jti and metadata are stored.

-- A registered MCP resource server (the audience of tokens). secret_hash
-- authenticates its introspection and decision calls.
CREATE TABLE IF NOT EXISTS mcp_resources (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  resource TEXT NOT NULL,
  name TEXT NOT NULL,
  secret_hash TEXT NOT NULL CHECK (length(secret_hash) = 64),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mcp_resources_uri ON mcp_resources (tenant_id, resource);

-- A client identified by a Client ID Metadata Document URL. The row is the
-- cache of the validated document (fetched through internal/safehttp) and the
-- admin's decision: a client is unusable until bound to an ai_agent identity
-- (the agent ceiling) and activated.
CREATE TABLE IF NOT EXISTS mcp_clients (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  client_id TEXT NOT NULL,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  jwks TEXT NOT NULL DEFAULT '{"keys":[]}',
  agent_identity_id INTEGER REFERENCES identities (id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
  doc_sha256 TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mcp_clients_client_id ON mcp_clients (tenant_id, client_id);

-- A pending authorization request, then its single-use code (code_hash).
CREATE TABLE IF NOT EXISTS mcp_auth_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT '',
  code_challenge TEXT NOT NULL,
  resource TEXT NOT NULL,
  scope TEXT NOT NULL,
  user_identity_id INTEGER NOT NULL REFERENCES identities (id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','redeemed')),
  code_hash TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mcp_auth_requests_code ON mcp_auth_requests (tenant_id, code_hash) WHERE code_hash IS NOT NULL;

-- An issued access token (the JWT itself is not stored). Introspection and
-- the kill switch work on this table.
CREATE TABLE IF NOT EXISTS mcp_tokens (
  jti TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  client_id TEXT NOT NULL,
  subject_identity_id INTEGER NOT NULL REFERENCES identities (id),
  agent_identity_id INTEGER NOT NULL REFERENCES identities (id),
  audience TEXT NOT NULL,
  scope TEXT NOT NULL,
  act TEXT NOT NULL,
  grant_type TEXT NOT NULL CHECK (grant_type IN ('authorization_code','token_exchange')),
  policy_version TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_mcp_tokens_agent ON mcp_tokens (tenant_id, agent_identity_id, revoked_at);
CREATE INDEX IF NOT EXISTS ix_mcp_tokens_subject ON mcp_tokens (tenant_id, subject_identity_id, revoked_at);

-- Every issue, exchange, denial and tool-call decision, with the policy
-- version. Identity ids are plain history (no foreign key: the log outlives
-- the identity).
CREATE TABLE IF NOT EXISTS mcp_decisions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  at TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('issue','exchange','tool_call','revoke')),
  decision TEXT NOT NULL CHECK (decision IN ('allow','deny')),
  reason TEXT NOT NULL DEFAULT '',
  jti TEXT NOT NULL DEFAULT '',
  client_id TEXT NOT NULL DEFAULT '',
  subject_identity_id INTEGER,
  agent_identity_id INTEGER,
  resource TEXT NOT NULL DEFAULT '',
  tool TEXT NOT NULL DEFAULT '',
  requested_scope TEXT NOT NULL DEFAULT '',
  granted_scope TEXT NOT NULL DEFAULT '',
  policy_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_mcp_decisions_at ON mcp_decisions (tenant_id, id);

-- A client's actor assertion may be used once.
CREATE TABLE IF NOT EXISTS mcp_actor_jtis (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  jti_hash TEXT NOT NULL CHECK (length(jti_hash) = 64),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, jti_hash)
);

CREATE TRIGGER IF NOT EXISTS tg_mcp_clients_xtenant_ins BEFORE INSERT ON mcp_clients
WHEN NEW.agent_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.agent_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_clients'); END;

CREATE TRIGGER IF NOT EXISTS tg_mcp_clients_xtenant_upd BEFORE UPDATE OF tenant_id, agent_identity_id ON mcp_clients
WHEN NEW.agent_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.agent_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_clients'); END;

CREATE TRIGGER IF NOT EXISTS tg_mcp_auth_requests_xtenant_ins BEFORE INSERT ON mcp_auth_requests
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.user_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_auth_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_mcp_auth_requests_xtenant_upd BEFORE UPDATE OF tenant_id, user_identity_id ON mcp_auth_requests
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.user_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_auth_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_mcp_tokens_xtenant_ins BEFORE INSERT ON mcp_tokens
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.subject_identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.agent_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_tokens'); END;

CREATE TRIGGER IF NOT EXISTS tg_mcp_tokens_xtenant_upd BEFORE UPDATE OF tenant_id, subject_identity_id, agent_identity_id ON mcp_tokens
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.subject_identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.agent_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_tokens'); END;
