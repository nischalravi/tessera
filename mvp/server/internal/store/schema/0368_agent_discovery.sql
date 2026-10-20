-- AI agent discovery (issue #116): where each discovered AI agent came from and
-- who created and sponsors it, and what a scan of source code found about MCP
-- servers and agent credentials.
--
-- Tenant-owned like every table of 0001_tenancy.sql: tenant_id references
-- tenants(id), every identity reference is guarded by a cross-tenant trigger.
--
-- Neither table holds a secret. agent_profiles keeps provenance (system,
-- kind, the creator's and sponsor's names as the source spells them).
-- mcp_findings keeps a location, a truncated hash (fingerprint) and the TYPE of
-- a secret; the scanner discards the value before anything is stored.
CREATE TABLE IF NOT EXISTS agent_profiles (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  kind TEXT NOT NULL,
  creator_ref TEXT NOT NULL DEFAULT '',
  creator_identity_id INTEGER REFERENCES identities (id),
  sponsor_ref TEXT NOT NULL DEFAULT '',
  sponsor_identity_id INTEGER REFERENCES identities (id),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source, external_id)
);
CREATE INDEX IF NOT EXISTS ix_agent_profiles_tenant_identity ON agent_profiles (tenant_id, identity_id);

CREATE TABLE IF NOT EXISTS mcp_findings (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  org TEXT NOT NULL,
  repo TEXT NOT NULL,
  path TEXT NOT NULL,
  location TEXT NOT NULL,
  server TEXT NOT NULL DEFAULT '',
  transport TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '',
  secret_type TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT '',
  owner_ref TEXT NOT NULL DEFAULT '',
  owner_source TEXT NOT NULL DEFAULT 'none',
  owner_identity_id INTEGER REFERENCES identities (id),
  commit_sha TEXT NOT NULL DEFAULT '',
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  UNIQUE (tenant_id, source, kind, org, repo, path, location, fingerprint)
);
CREATE INDEX IF NOT EXISTS ix_mcp_findings_tenant_source ON mcp_findings (tenant_id, source);

CREATE TRIGGER IF NOT EXISTS tg_agent_profiles_xtenant_ins BEFORE INSERT ON agent_profiles
WHEN (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.creator_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.creator_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.sponsor_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_profiles'); END;

CREATE TRIGGER IF NOT EXISTS tg_agent_profiles_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, creator_identity_id, sponsor_identity_id ON agent_profiles
WHEN (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.creator_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.creator_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.sponsor_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_profiles'); END;

CREATE TRIGGER IF NOT EXISTS tg_mcp_findings_xtenant_ins BEFORE INSERT ON mcp_findings
WHEN NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_findings'); END;

CREATE TRIGGER IF NOT EXISTS tg_mcp_findings_xtenant_upd BEFORE UPDATE OF tenant_id, owner_identity_id ON mcp_findings
WHEN NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_findings'); END;
