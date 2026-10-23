-- Credential, permission and owner changes of third-party OAuth apps (issue #474).
-- Storm-0940 used compromised vendor cloud-app identities to add credentials to
-- customers' OAuth apps, so the inventory of #107 also keeps what an app holds
-- besides grants, and records what changed between two syncs.
--
-- oauth_app_facts has one row per thing an app holds that a sync compares:
-- a client secret, a certificate or an owner, each with the provider's key. A
-- 'baseline' row (one per app) marks that the app was synced once with this
-- feature on, so what an app held before the first sync is never reported as a
-- change. A fact a later sync no longer lists is marked 'removed', never deleted.
--
-- oauth_app_changes has one row per detected change: a credential added, a
-- permission granted (an app role or an admin consent) or an owner changed. It
-- stays 'open' until the credential or grant is gone, or the owner change is
-- acknowledged, so the OAuth apps panel can show it and offer containment.
-- subject is the fact id, the grant id or the new owner's key.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's app.
CREATE TABLE IF NOT EXISTS oauth_app_facts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  app_id TEXT NOT NULL REFERENCES oauth_apps (id),
  kind TEXT NOT NULL CHECK (kind IN ('baseline','secret','certificate','owner')),
  fact_key TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  provider_ref TEXT NOT NULL DEFAULT '',
  added_at TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','removed'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_oauth_app_facts_key ON oauth_app_facts (tenant_id, app_id, kind, fact_key);

CREATE TABLE IF NOT EXISTS oauth_app_changes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  app_id TEXT NOT NULL REFERENCES oauth_apps (id),
  kind TEXT NOT NULL CHECK (kind IN ('credential_added','permission_granted','owner_changed')),
  subject TEXT NOT NULL,
  summary TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  detected_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
  resolved_at TEXT,
  resolution TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_oauth_app_changes_key ON oauth_app_changes (tenant_id, app_id, kind, subject);
CREATE INDEX IF NOT EXISTS ix_oauth_app_changes_status ON oauth_app_changes (tenant_id, status, detected_at);

CREATE TRIGGER IF NOT EXISTS tg_oauth_app_facts_xtenant_ins BEFORE INSERT ON oauth_app_facts
WHEN EXISTS (SELECT 1 FROM oauth_apps p WHERE p.id = NEW.app_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_app_facts'); END;

CREATE TRIGGER IF NOT EXISTS tg_oauth_app_facts_xtenant_upd BEFORE UPDATE OF tenant_id, app_id ON oauth_app_facts
WHEN EXISTS (SELECT 1 FROM oauth_apps p WHERE p.id = NEW.app_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_app_facts'); END;

CREATE TRIGGER IF NOT EXISTS tg_oauth_app_changes_xtenant_ins BEFORE INSERT ON oauth_app_changes
WHEN EXISTS (SELECT 1 FROM oauth_apps p WHERE p.id = NEW.app_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_app_changes'); END;

CREATE TRIGGER IF NOT EXISTS tg_oauth_app_changes_xtenant_upd BEFORE UPDATE OF tenant_id, app_id ON oauth_app_changes
WHEN EXISTS (SELECT 1 FROM oauth_apps p WHERE p.id = NEW.app_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_app_changes'); END;
