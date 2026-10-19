-- Request access drafts: a request a person is still putting together (the
-- cart on Access > Request access, saved to come back to later).
--
-- One row per draft, private to the platform user who saved it. A draft names
-- people (beneficiary_ids, JSON array of identity ids) and items (items, JSON
-- array of {"kind":"group","group_id":N} or {"kind":"role","role_id":"..."});
-- the API checks they exist when the draft is saved and resolves their names
-- when it is read. A draft never becomes a request by itself: submitting is a
-- separate call to POST /api/requests or /api/role-requests, after which the
-- client deletes the draft.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's user.
CREATE TABLE IF NOT EXISTS request_drafts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  beneficiary_ids TEXT NOT NULL DEFAULT '[]',
  items TEXT NOT NULL DEFAULT '[]',
  duration_hours REAL CHECK (duration_hours IS NULL OR duration_hours > 0),
  justification TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_request_drafts_tenant_user ON request_drafts (tenant_id, user_id, updated_at);

CREATE TRIGGER IF NOT EXISTS tg_request_drafts_xtenant_ins BEFORE INSERT ON request_drafts
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: request_drafts'); END;

CREATE TRIGGER IF NOT EXISTS tg_request_drafts_xtenant_upd BEFORE UPDATE OF tenant_id, user_id ON request_drafts
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: request_drafts'); END;
