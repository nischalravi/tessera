-- Group privileges (issue #47, GR-4; design docs/design/groups-grouper-parity.md
-- §5.3, §7). The design numbers this file 0102; 0280..0284 are taken here, so it
-- is 0285.
--
-- A grp_privileges row says that a holder (an identity, every effective member
-- of a group, or everyone) holds a privilege on an object (a folder, a group or,
-- from GR-7, an attribute definition). A row on a folder with applies_to
-- groups, folders or attr_defs and scope one or sub is inherited at check time
-- by the objects below it; it is never copied (K5).
--
-- object_id names a folder or a group by object_type, with no foreign key (a
-- group is soft-deleted, a folder's rows are deleted with it), so the guard
-- triggers check the tenant. Every unique index starts with tenant_id.

CREATE TABLE IF NOT EXISTS grp_privileges (
  id                 TEXT PRIMARY KEY,
  tenant_id          TEXT NOT NULL REFERENCES tenants (id),
  object_type        TEXT NOT NULL CHECK (object_type IN ('folder','group','attr_def')),
  object_id          TEXT NOT NULL,
  privilege          TEXT NOT NULL CHECK (privilege IN (
     'admin','update','read','view','optin','optout','group_attr_read','group_attr_update',
     'stem_admin','create','stem_attr_read','stem_attr_update','stem_view',
     'attr_admin','attr_update','attr_read','attr_view','attr_optin','attr_optout',
     'attr_def_attr_read','attr_def_attr_update')),
  holder_type        TEXT NOT NULL CHECK (holder_type IN ('identity','group','everyone')),
  holder_identity_id INTEGER REFERENCES identities (id),
  holder_group_id    TEXT REFERENCES grp_groups (id),
  applies_to         TEXT NOT NULL DEFAULT 'self'
                     CHECK (applies_to IN ('self','groups','folders','attr_defs')),
  scope              TEXT NOT NULL DEFAULT 'self' CHECK (scope IN ('self','one','sub')),
  source             TEXT NOT NULL CHECK (source IN ('ui','api','creator_default','grouper_import','template')),
  created_by         TEXT,
  created_at         TEXT NOT NULL,
  CHECK ((applies_to = 'self') = (scope = 'self')),
  CHECK (applies_to = 'self' OR object_type = 'folder'),
  CHECK ((holder_type = 'identity') = (holder_identity_id IS NOT NULL)),
  CHECK ((holder_type = 'group') = (holder_group_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS grp_priv_object ON grp_privileges (tenant_id, object_type, object_id);
CREATE INDEX IF NOT EXISTS grp_priv_holder_g ON grp_privileges (tenant_id, holder_group_id);
CREATE INDEX IF NOT EXISTS grp_priv_holder_i ON grp_privileges (tenant_id, holder_identity_id);

-- a grant is made once: one partial unique index per kind of holder
CREATE UNIQUE INDEX IF NOT EXISTS grp_priv_once_identity ON grp_privileges
  (tenant_id, object_type, object_id, privilege, applies_to, scope, holder_identity_id) WHERE holder_type = 'identity';
CREATE UNIQUE INDEX IF NOT EXISTS grp_priv_once_group ON grp_privileges
  (tenant_id, object_type, object_id, privilege, applies_to, scope, holder_group_id) WHERE holder_type = 'group';
CREATE UNIQUE INDEX IF NOT EXISTS grp_priv_once_everyone ON grp_privileges
  (tenant_id, object_type, object_id, privilege, applies_to, scope) WHERE holder_type = 'everyone';

-- Groups privilege settings, one row per tenant (Admin > Groups settings, §7.2,
-- G-40): the privileges that may be granted to everyone, and the grants made to
-- everyone on every new object. body is JSON, validated by internal/groups/privs.
CREATE TABLE IF NOT EXISTS grp_priv_settings (
  tenant_id  TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  body       TEXT NOT NULL CHECK (json_valid(body)),
  updated_at TEXT NOT NULL,
  updated_by TEXT
);

-- ---------------------------------------------------------------- cross-tenant guards

CREATE TRIGGER IF NOT EXISTS tg_grp_privileges_xtenant_ins BEFORE INSERT ON grp_privileges
WHEN (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.holder_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.holder_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.holder_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.holder_group_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_privileges'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_privileges_xtenant_upd BEFORE UPDATE OF tenant_id, object_type, object_id, holder_identity_id, holder_group_id ON grp_privileges
WHEN (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.holder_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.holder_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.holder_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.holder_group_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_privileges'); END;
