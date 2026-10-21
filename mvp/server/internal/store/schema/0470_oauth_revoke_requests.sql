-- Pending four-eyes revokes of third-party OAuth apps (issue #107). Revoking
-- more than one grant of an app that holds a high or critical scope, or every
-- app of a vendor, cuts SaaS access across the tenant, so a second admin must
-- make the same request: the first admin's request waits here, the same admin
-- repeating it is refused, and a second admin's identical request executes it.
--
-- scope is 'app' (target is the oauth_apps id) or 'vendor' (target is the
-- lower-cased publisher or app name). grants and apps are what the request
-- covered when it was made. A pending row past expires_at is never executed.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's user.
CREATE TABLE IF NOT EXISTS oauth_revoke_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  scope TEXT NOT NULL CHECK (scope IN ('app','vendor')),
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  apps INTEGER NOT NULL DEFAULT 0,
  grants INTEGER NOT NULL DEFAULT 0,
  requested_by_user_id TEXT NOT NULL REFERENCES platform_users (id),
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','executed','expired')),
  decided_by_user_id TEXT REFERENCES platform_users (id),
  decided_by TEXT,
  decided_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_oauth_revoke_requests_target ON oauth_revoke_requests (tenant_id, scope, target, status);

CREATE TRIGGER IF NOT EXISTS tg_oauth_revoke_requests_xtenant_ins BEFORE INSERT ON oauth_revoke_requests
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_revoke_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_oauth_revoke_requests_xtenant_upd BEFORE UPDATE OF tenant_id, requested_by_user_id, decided_by_user_id ON oauth_revoke_requests
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: oauth_revoke_requests'); END;
