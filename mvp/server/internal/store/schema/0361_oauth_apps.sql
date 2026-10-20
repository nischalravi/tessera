-- Third-party OAuth app and grant inventory (issue #107): the apps users and
-- admins authorized in Google Workspace, Microsoft Entra ID, Salesforce and
-- GitHub, and every grant they hold, with a scope risk score and a revoke
-- trail.
--
-- oauth_apps has one row per app per provider (provider + client_id). Its
-- risk_score (0-100) and risk_reasons (JSON array of strings) are computed by
-- internal/oauthapps from the active grants. owner_identity_id names the
-- identity accountable for the app; the app is a non-human identity in the
-- NHI inventory (kind oauth_app).
--
-- oauth_grants has one row per grant: a user's consent, an admin consent, an
-- application permission, a GitHub app installation or a credential
-- authorization. A grant that disappears from a full successful sync is marked
-- 'removed', never deleted, so history is kept. identity_id and account_id are
-- set when the granting user was correlated to an account; user_ref is always
-- the provider's own reference to the user.
--
-- oauth_sync_state records the last sync of each provider, so a failed sync is
-- visible and never mistaken for an empty provider.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's row.
CREATE TABLE IF NOT EXISTS oauth_apps (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provider TEXT NOT NULL CHECK (provider IN ('google','entra','salesforce','github')),
  client_id TEXT NOT NULL,
  name TEXT NOT NULL,
  publisher TEXT NOT NULL DEFAULT '',
  verified INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0,1)),
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  last_used TEXT,
  owner_identity_id INTEGER REFERENCES identities (id),
  risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  risk_reasons TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','removed')),
  revoked_at TEXT,
  revoked_by TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_oauth_apps_key ON oauth_apps (tenant_id, provider, client_id);
CREATE INDEX IF NOT EXISTS ix_oauth_apps_publisher ON oauth_apps (tenant_id, publisher);

CREATE TABLE IF NOT EXISTS oauth_grants (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  app_id TEXT NOT NULL REFERENCES oauth_apps (id),
  provider TEXT NOT NULL CHECK (provider IN ('google','entra','salesforce','github')),
  grant_key TEXT NOT NULL,
  provider_ref TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL CHECK (kind IN ('token','delegated','app_role','installation','credential')),
  identity_id INTEGER REFERENCES identities (id),
  account_id INTEGER REFERENCES accounts (id),
  user_ref TEXT NOT NULL DEFAULT '',
  granter_admin INTEGER NOT NULL DEFAULT 0 CHECK (granter_admin IN (0,1)),
  scopes TEXT NOT NULL DEFAULT '[]',
  consent_type TEXT NOT NULL CHECK (consent_type IN ('user','admin')),
  granted_at TEXT,
  last_used TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','removed','revoked','revoke_failed')),
  revoked_at TEXT,
  revoked_by TEXT,
  revoke_error TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_oauth_grants_key ON oauth_grants (tenant_id, app_id, grant_key);
CREATE INDEX IF NOT EXISTS ix_oauth_grants_app ON oauth_grants (tenant_id, app_id, status);
CREATE INDEX IF NOT EXISTS ix_oauth_grants_provider ON oauth_grants (tenant_id, provider, status);

CREATE TABLE IF NOT EXISTS oauth_sync_state (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provider TEXT NOT NULL CHECK (provider IN ('google','entra','salesforce','github')),
  status TEXT NOT NULL CHECK (status IN ('ok','failed')),
  attempted_at TEXT NOT NULL,
  succeeded_at TEXT,
  apps INTEGER NOT NULL DEFAULT 0,
  grants INTEGER NOT NULL DEFAULT 0,
  removed INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, provider)
);

CREATE TRIGGER IF NOT EXISTS tg_oauth_apps_xtenant_ins BEFORE INSERT ON oauth_apps
WHEN NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_apps'); END;

CREATE TRIGGER IF NOT EXISTS tg_oauth_apps_xtenant_upd BEFORE UPDATE OF tenant_id, owner_identity_id ON oauth_apps
WHEN NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_apps'); END;

CREATE TRIGGER IF NOT EXISTS tg_oauth_grants_xtenant_ins BEFORE INSERT ON oauth_grants
WHEN EXISTS (SELECT 1 FROM oauth_apps p WHERE p.id = NEW.app_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_grants'); END;

CREATE TRIGGER IF NOT EXISTS tg_oauth_grants_xtenant_upd BEFORE UPDATE OF tenant_id, app_id, identity_id, account_id ON oauth_grants
WHEN EXISTS (SELECT 1 FROM oauth_apps p WHERE p.id = NEW.app_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_grants'); END;
