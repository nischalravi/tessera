-- Postgres dialect of schema/0361_oauth_apps.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Composite (tenant_id, id) foreign keys replace the
-- SQLite cross-tenant guard triggers.

-- +goose Up

CREATE TABLE oauth_apps (
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
  owner_identity_id BIGINT,
  risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  risk_reasons TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','removed')),
  revoked_at TEXT,
  revoked_by TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_identity_id) REFERENCES identities (tenant_id, id)
);
CREATE UNIQUE INDEX ux_oauth_apps_key ON oauth_apps (tenant_id, provider, client_id);
CREATE INDEX ix_oauth_apps_publisher ON oauth_apps (tenant_id, publisher);

CREATE TABLE oauth_grants (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  app_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('google','entra','salesforce','github')),
  grant_key TEXT NOT NULL,
  provider_ref TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL CHECK (kind IN ('token','delegated','app_role','installation','credential')),
  identity_id BIGINT,
  account_id BIGINT,
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
  revoke_error TEXT NOT NULL DEFAULT '',
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, app_id) REFERENCES oauth_apps (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id)
);
CREATE UNIQUE INDEX ux_oauth_grants_key ON oauth_grants (tenant_id, app_id, grant_key);
CREATE INDEX ix_oauth_grants_app ON oauth_grants (tenant_id, app_id, status);
CREATE INDEX ix_oauth_grants_provider ON oauth_grants (tenant_id, provider, status);

CREATE TABLE oauth_sync_state (
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
