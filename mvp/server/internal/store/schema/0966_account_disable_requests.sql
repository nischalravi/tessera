-- Who asked for the last disable of an account through the account route (POST /api/accounts/.../disable, issue #915),
-- so a re-enable of that account needs a different person (four eyes, like Enable of an identity, #316). One row per
-- account; a later disable request replaces it. requested_by is the actor name; requested_by_user_id the platform user
-- when there was one (two users linked to one identity count as one person, #425).
--
-- Tenant-owned: tenant_id on every row and first in the key. The guard triggers refuse a reference to another tenant's
-- account or user. Postgres: migration 0973.
CREATE TABLE IF NOT EXISTS account_disable_requests (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  requested_by TEXT NOT NULL,
  requested_by_user_id TEXT REFERENCES platform_users (id),
  requested_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, account_id)
);

CREATE TRIGGER IF NOT EXISTS tg_account_disable_requests_xtenant_ins BEFORE INSERT ON account_disable_requests
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.requested_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: account_disable_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_account_disable_requests_xtenant_upd BEFORE UPDATE OF tenant_id, account_id, requested_by_user_id ON account_disable_requests
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.requested_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: account_disable_requests'); END;
