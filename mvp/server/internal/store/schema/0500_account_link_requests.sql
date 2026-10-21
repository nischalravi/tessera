-- Pending pins and releases of a connector account's identity (issue #376,
-- following #357/#382 for platform users). Pinning an account to a person, or
-- releasing the pin, changes whose access the account counts as, so it needs
-- two admins with identities.correlate: the first admin's request waits here
-- and a second admin's identical request applies it (and deletes the row).
--
-- One pending row per account. action 'link' carries identity_id (the person
-- the account is pinned to) and a reason; action 'release' has neither.
-- previous_identity_id is the account's identity when the request was made,
-- so a request made stale by another change is never applied. A row past
-- expires_at is ignored and replaced by the next request.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's account, identity or user.
CREATE TABLE IF NOT EXISTS account_link_requests (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  action TEXT NOT NULL CHECK (action IN ('link','release')),
  identity_id INTEGER REFERENCES identities (id),
  previous_identity_id INTEGER REFERENCES identities (id),
  reason TEXT NOT NULL,
  requested_by_user_id TEXT NOT NULL REFERENCES platform_users (id),
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  CHECK ((action = 'link') = (identity_id IS NOT NULL)),
  PRIMARY KEY (tenant_id, account_id)
);

CREATE TRIGGER IF NOT EXISTS tg_account_link_requests_xtenant_ins BEFORE INSERT ON account_link_requests
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: account_link_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_account_link_requests_xtenant_upd BEFORE UPDATE OF tenant_id, account_id, identity_id, previous_identity_id, requested_by_user_id ON account_link_requests
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: account_link_requests'); END;
