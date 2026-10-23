-- Postgres dialect of schema/0830_agent_blueprints.sql (issue #478). Cross-tenant guard
-- triggers become composite foreign keys; see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE agent_blueprints (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  app_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  creator_ref TEXT NOT NULL DEFAULT '',
  sponsor_ref TEXT NOT NULL DEFAULT '',
  sponsor_identity_id BIGINT,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source, external_id),
  FOREIGN KEY (tenant_id, sponsor_identity_id) REFERENCES identities (tenant_id, id)
);

CREATE TABLE agent_links (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  blueprint_app_id TEXT NOT NULL DEFAULT '',
  manager_applications TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, source, external_id)
);
