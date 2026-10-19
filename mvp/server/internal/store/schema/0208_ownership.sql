-- Ownership of applications, entitlements and machine identities (issue #167).
--
-- One row per owned object: kind 'app' (object_key = the system name),
-- 'group' (an entitlement; object_key = groups.id), 'resource'
-- (resources.id) or 'identity' (a machine identity or agent; identities.id).
-- The primary owner is a person; the backup owner is a person; owner_group_id
-- optionally names a group whose members co-own it. purpose says why the
-- object exists. For an identity the primary owner is also kept in
-- identities.owner_id (what policies, reviews and the leaver plan read), and
-- connector sync does not overwrite an owner set here.
CREATE TABLE IF NOT EXISTS ownerships (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  object_kind TEXT NOT NULL CHECK (object_kind IN ('app','group','resource','identity')),
  object_key TEXT NOT NULL,
  primary_owner_id INTEGER REFERENCES identities (id),
  backup_owner_id INTEGER REFERENCES identities (id),
  owner_group_id INTEGER REFERENCES groups (id),
  purpose TEXT NOT NULL DEFAULT '',
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  CHECK (primary_owner_id IS NULL OR backup_owner_id IS NULL OR primary_owner_id <> backup_owner_id),
  PRIMARY KEY (tenant_id, object_kind, object_key)
);
CREATE INDEX IF NOT EXISTS ix_ownerships_tenant_primary ON ownerships (tenant_id, primary_owner_id);
CREATE INDEX IF NOT EXISTS ix_ownerships_tenant_backup ON ownerships (tenant_id, backup_owner_id);

CREATE TRIGGER IF NOT EXISTS tg_ownerships_xtenant_ins BEFORE INSERT ON ownerships
WHEN (NEW.primary_owner_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.primary_owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.backup_owner_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.backup_owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.owner_group_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: ownerships'); END;

CREATE TRIGGER IF NOT EXISTS tg_ownerships_xtenant_upd BEFORE UPDATE OF tenant_id, primary_owner_id, backup_owner_id, owner_group_id, updated_by ON ownerships
WHEN (NEW.primary_owner_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.primary_owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.backup_owner_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.backup_owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.owner_group_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: ownerships'); END;
