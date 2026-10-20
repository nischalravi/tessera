-- Pending changes of a platform user's identity link (issue #357). The link
-- decides the user's group privileges, whether sign-in is refused for an
-- inactive identity, and every "is this you?" check (self-approval, SoD
-- exemption, help-desk own identity). Changing or removing an existing link
-- therefore needs two tenant admins: the first admin's request waits here and
-- a second admin's identical change applies it.
--
-- One pending row per user. identity_id NULL is a request to remove the
-- link; previous_identity_id is the link the request was made against, so a
-- request made stale by another change is never applied.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's user or identity.
CREATE TABLE IF NOT EXISTS identity_link_requests (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  identity_id INTEGER REFERENCES identities (id),
  previous_identity_id INTEGER REFERENCES identities (id),
  requested_by_user_id TEXT NOT NULL REFERENCES platform_users (id),
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TRIGGER IF NOT EXISTS tg_identity_link_requests_xtenant_ins BEFORE INSERT ON identity_link_requests
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_link_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_link_requests_xtenant_upd BEFORE UPDATE OF tenant_id, user_id, identity_id, previous_identity_id, requested_by_user_id ON identity_link_requests
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_link_requests'); END;
