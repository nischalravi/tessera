-- Postgres dialect of schema/0720_helpdesk_auth_method_risk.sql (issue #477). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE helpdesk_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  recent_method_days INTEGER NOT NULL DEFAULT 7 CHECK (recent_method_days BETWEEN 1 AND 90),
  recent_method_action TEXT NOT NULL DEFAULT 'require_approval' CHECK (recent_method_action IN ('off','require_approval','block')),
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);

CREATE TABLE helpdesk_idp_risks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('auth_method_added')),
  source TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  occurred_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX ix_helpdesk_idp_risks_identity ON helpdesk_idp_risks (tenant_id, identity_id, occurred_at);
