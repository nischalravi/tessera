-- Entra Agent ID blueprints and agent relations (issue #478, extends 0375).
--
-- agent_blueprints: the blueprint (the template an Entra agent identity is
-- created from) with its sponsor, as the source spells them.
-- agent_links: per discovered agent, the appId of the blueprint it was created from
-- (Entra agentIdentityBlueprintId, which is the blueprint's appId, not its object id)
-- and its managerApplications (application ids, comma separated; applications, not
-- people). One row per agent_profiles key.
--
-- Tenant-owned like every table of 0001_tenancy.sql; identity references are
-- guarded by cross-tenant triggers. No secret values are stored.
CREATE TABLE IF NOT EXISTS agent_blueprints (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  app_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  creator_ref TEXT NOT NULL DEFAULT '',
  sponsor_ref TEXT NOT NULL DEFAULT '',
  sponsor_identity_id INTEGER REFERENCES identities (id),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source, external_id)
);

CREATE TABLE IF NOT EXISTS agent_links (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  blueprint_app_id TEXT NOT NULL DEFAULT '',
  manager_applications TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, source, external_id)
);

CREATE TRIGGER IF NOT EXISTS tg_agent_blueprints_xtenant_ins BEFORE INSERT ON agent_blueprints
WHEN NEW.sponsor_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_blueprints'); END;

CREATE TRIGGER IF NOT EXISTS tg_agent_blueprints_xtenant_upd BEFORE UPDATE OF tenant_id, sponsor_identity_id ON agent_blueprints
WHEN NEW.sponsor_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: agent_blueprints'); END;
