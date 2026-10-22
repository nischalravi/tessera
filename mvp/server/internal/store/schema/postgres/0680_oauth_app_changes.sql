-- Postgres dialect of schema/0680_oauth_app_changes.sql (issue #474). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE oauth_app_facts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  app_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('baseline','secret','certificate','owner')),
  fact_key TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  provider_ref TEXT NOT NULL DEFAULT '',
  added_at TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','removed')),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, app_id) REFERENCES oauth_apps (tenant_id, id)
);
CREATE UNIQUE INDEX ux_oauth_app_facts_key ON oauth_app_facts (tenant_id, app_id, kind, fact_key);

CREATE TABLE oauth_app_changes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  app_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('credential_added','permission_granted','owner_changed')),
  subject TEXT NOT NULL,
  summary TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  detected_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
  resolved_at TEXT,
  resolution TEXT NOT NULL DEFAULT '',
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, app_id) REFERENCES oauth_apps (tenant_id, id)
);
CREATE UNIQUE INDEX ux_oauth_app_changes_key ON oauth_app_changes (tenant_id, app_id, kind, subject);
CREATE INDEX ix_oauth_app_changes_status ON oauth_app_changes (tenant_id, status, detected_at);
