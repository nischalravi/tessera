-- Postgres dialect of schema/0710_github_tokens.sql (issue #476). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE github_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  token_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('classic_pat','fine_grained_pat','oauth_app_token','actions_secret')),
  name TEXT NOT NULL,
  owner_login TEXT NOT NULL DEFAULT '',
  owner_identity_id BIGINT,
  scopes TEXT NOT NULL DEFAULT '[]',
  visibility TEXT NOT NULL DEFAULT '',
  created_at TEXT,
  rotated_at TEXT,
  expires_at TEXT,
  last_used_at TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','removed')),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_identity_id) REFERENCES identities (tenant_id, id)
);
CREATE UNIQUE INDEX ux_github_tokens_key ON github_tokens (tenant_id, token_key);
CREATE INDEX ix_github_tokens_status ON github_tokens (tenant_id, status);
