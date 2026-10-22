-- Identity disable / enable (preview wiring): the record of one Disable of a
-- person, so Enable restores exactly what Disable changed and nothing else.
--
-- identity_disables: one row per Disable. enabled_at is NULL while the
-- identity is disabled; a partial unique index allows one open row per
-- identity. containment_status is the roll-up of the containment run that
-- went with it (complete, retrying, manual, none).
--
-- identity_disable_accounts: the accounts that were active when Disable ran
-- and were set to disabled. Enable sets back only these, and only those still
-- disabled; an account disabled by a leaver plan, a review or a connector is
-- never re-enabled by Enable.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's identity or account.
CREATE TABLE IF NOT EXISTS identity_disables (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  reason TEXT NOT NULL,
  disabled_by TEXT NOT NULL,
  disabled_by_user_id TEXT,
  disabled_at TEXT NOT NULL,
  containment_status TEXT NOT NULL DEFAULT 'none',
  enabled_by TEXT,
  enabled_at TEXT,
  enable_reason TEXT
);
CREATE INDEX IF NOT EXISTS ix_identity_disables_tenant_identity ON identity_disables (tenant_id, identity_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_disables_open ON identity_disables (tenant_id, identity_id) WHERE enabled_at IS NULL;

CREATE TABLE IF NOT EXISTS identity_disable_accounts (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  disable_id TEXT NOT NULL REFERENCES identity_disables (id),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  PRIMARY KEY (tenant_id, disable_id, account_id)
);

CREATE TRIGGER IF NOT EXISTS tg_identity_disables_xtenant_ins BEFORE INSERT ON identity_disables
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_disables'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_disables_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON identity_disables
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_disables'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_disable_accounts_xtenant_ins BEFORE INSERT ON identity_disable_accounts
WHEN EXISTS (SELECT 1 FROM identity_disables p WHERE p.id = NEW.disable_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_disable_accounts'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_disable_accounts_xtenant_upd BEFORE UPDATE OF tenant_id, disable_id, account_id ON identity_disable_accounts
WHEN EXISTS (SELECT 1 FROM identity_disables p WHERE p.id = NEW.disable_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_disable_accounts'); END;
