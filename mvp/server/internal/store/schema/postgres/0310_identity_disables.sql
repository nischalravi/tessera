-- Postgres dialect of schema/0310_identity_disables.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE identity_disables (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  reason TEXT NOT NULL,
  disabled_by TEXT NOT NULL,
  disabled_at TEXT NOT NULL,
  containment_status TEXT NOT NULL DEFAULT 'none',
  enabled_by TEXT,
  enabled_at TEXT,
  enable_reason TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX ix_identity_disables_tenant_identity ON identity_disables (tenant_id, identity_id);
CREATE UNIQUE INDEX ux_identity_disables_open ON identity_disables (tenant_id, identity_id) WHERE enabled_at IS NULL;

CREATE TABLE identity_disable_accounts (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  disable_id TEXT NOT NULL,
  account_id BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, disable_id, account_id),
  FOREIGN KEY (tenant_id, disable_id) REFERENCES identity_disables (tenant_id, id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id)
);
