-- Native groups (issue #44, GR-1; design docs/design/groups-grouper-parity.md
-- §5.3). Folders, name aliases, groups, composite factors, lists and direct
-- memberships, plus the engine tables (dependency DAG, closure, levels,
-- effective membership, engine queue). The engine tables are created empty:
-- the membership engine (GR-2) fills them.
--
-- Native groups are NOT the connected-system `groups` table: that holds groups
-- read from Okta, AWS and so on. These are owned by Tessera.
--
-- Tenant-owned like 0001_tenancy.sql: every table has tenant_id, every unique
-- constraint starts with it, and the guard triggers at the end refuse a
-- reference to another tenant's row.
--
-- Names are ':'-separated paths and unique per tenant case-insensitively. A
-- folder and a group share one name space, which the model layer checks; the
-- unique indexes here are the per-table backstop.

CREATE TABLE IF NOT EXISTS grp_folders (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  parent_id TEXT REFERENCES grp_folders (id),
  -- '' only for the tenant root
  extension TEXT NOT NULL CHECK (length(extension) BETWEEN 0 AND 255
    AND (extension = '' OR extension NOT GLOB '*[^A-Za-z0-9_.-]*')),
  display_extension TEXT NOT NULL,
  name TEXT NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  id_index INTEGER NOT NULL,
  object_types TEXT NOT NULL DEFAULT '[]',
  data_owner TEXT,
  managed_by TEXT NOT NULL DEFAULT 'ui'
    CHECK (managed_by IN ('ui','policy_repo','loader','grouper_mirror','connector')),
  external_ref TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id_index),
  CHECK ((parent_id IS NULL) = (extension = ''))
);
CREATE UNIQUE INDEX IF NOT EXISTS grp_folders_ci ON grp_folders (tenant_id, lower(name));
-- one root folder per tenant
CREATE UNIQUE INDEX IF NOT EXISTS grp_folders_root ON grp_folders (tenant_id) WHERE parent_id IS NULL;
CREATE INDEX IF NOT EXISTS grp_folders_parent ON grp_folders (tenant_id, parent_id);

-- old names after a move or rename (G-02): they keep resolving and stay reserved
CREATE TABLE IF NOT EXISTS grp_name_aliases (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group')),
  object_id TEXT NOT NULL,
  old_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, object_type, old_name)
);
-- folders and groups share one name space
CREATE UNIQUE INDEX IF NOT EXISTS grp_name_aliases_ci ON grp_name_aliases (tenant_id, lower(old_name));
CREATE INDEX IF NOT EXISTS grp_name_aliases_object ON grp_name_aliases (tenant_id, object_type, object_id);

CREATE TABLE IF NOT EXISTS grp_groups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  folder_id TEXT NOT NULL REFERENCES grp_folders (id),
  extension TEXT NOT NULL CHECK (length(extension) BETWEEN 1 AND 255 AND extension NOT GLOB '*[^A-Za-z0-9_.-]*'),
  display_extension TEXT NOT NULL,
  name TEXT NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  id_index INTEGER NOT NULL,
  kind TEXT NOT NULL DEFAULT 'group' CHECK (kind IN ('group','role')),
  definition TEXT NOT NULL DEFAULT 'basic' CHECK (definition IN ('basic','composite','policy')),
  composite_op TEXT CHECK (composite_op IN ('union','intersection','complement')),
  -- JSON {path, commit, compiled_sha256}
  policy_ref TEXT,
  managed_by TEXT NOT NULL DEFAULT 'ui'
    CHECK (managed_by IN ('ui','policy_repo','loader','grouper_mirror','connector')),
  loader_id TEXT,
  object_types TEXT NOT NULL DEFAULT '[]',
  data_owner TEXT,
  member_description TEXT,
  enabled_from TEXT,
  disabled_at TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','deleted')),
  requestable INTEGER NOT NULL DEFAULT 0,
  effective_count INTEGER NOT NULL DEFAULT 0,
  effective_version INTEGER NOT NULL DEFAULT 0,
  recompute_state TEXT NOT NULL DEFAULT 'clean' CHECK (recompute_state IN ('clean','pending','failed')),
  external_ref TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id_index),
  CHECK ((definition = 'composite') = (composite_op IS NOT NULL)),
  CHECK ((definition = 'policy') = (policy_ref IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS grp_groups_ci ON grp_groups (tenant_id, lower(name));
CREATE INDEX IF NOT EXISTS grp_groups_folder ON grp_groups (tenant_id, folder_id);

CREATE TABLE IF NOT EXISTS grp_composite_factors (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL REFERENCES grp_groups (id),
  -- complement: 0 = left, 1 = right
  position INTEGER NOT NULL,
  factor_group_id TEXT NOT NULL REFERENCES grp_groups (id),
  PRIMARY KEY (tenant_id, group_id, position)
);

-- custom lists (G-25); the built-in 'members' list has a fixed per-tenant id
CREATE TABLE IF NOT EXISTS grp_lists (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  read_priv TEXT NOT NULL DEFAULT 'read',
  write_priv TEXT NOT NULL DEFAULT 'update',
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS grp_direct_memberships (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL REFERENCES grp_groups (id),
  list_id TEXT NOT NULL REFERENCES grp_lists (id),
  member_type TEXT NOT NULL CHECK (member_type IN ('identity','group')),
  member_identity_id INTEGER REFERENCES identities (id),
  member_group_id TEXT REFERENCES grp_groups (id),
  enabled_from TEXT,
  disabled_at TEXT,
  source TEXT NOT NULL,
  source_ref TEXT,
  reason TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  CHECK ((member_type = 'identity') = (member_identity_id IS NOT NULL)),
  CHECK ((member_type = 'group') = (member_group_id IS NOT NULL)),
  CHECK (disabled_at IS NULL OR enabled_from IS NULL OR disabled_at > enabled_from)
);
CREATE UNIQUE INDEX IF NOT EXISTS grp_dm_ident ON grp_direct_memberships (tenant_id, group_id, list_id, member_identity_id)
  WHERE member_type = 'identity';
CREATE UNIQUE INDEX IF NOT EXISTS grp_dm_group ON grp_direct_memberships (tenant_id, group_id, list_id, member_group_id)
  WHERE member_type = 'group';
CREATE INDEX IF NOT EXISTS grp_dm_by_identity ON grp_direct_memberships (tenant_id, member_identity_id);
CREATE INDEX IF NOT EXISTS grp_dm_enable ON grp_direct_memberships (tenant_id, enabled_from) WHERE enabled_from IS NOT NULL;
CREATE INDEX IF NOT EXISTS grp_dm_disable ON grp_direct_memberships (tenant_id, disabled_at) WHERE disabled_at IS NOT NULL;

-- Engine tables (GR-2 fills them; empty until then).

-- dependency DAG: child feeds parent, by nesting or as a composite factor
CREATE TABLE IF NOT EXISTS grp_deps (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  parent_group_id TEXT NOT NULL REFERENCES grp_groups (id),
  child_group_id TEXT NOT NULL REFERENCES grp_groups (id),
  kind TEXT NOT NULL CHECK (kind IN ('nest','factor')),
  list_id TEXT NOT NULL REFERENCES grp_lists (id),
  PRIMARY KEY (tenant_id, parent_group_id, child_group_id, kind, list_id)
);
CREATE INDEX IF NOT EXISTS grp_deps_child ON grp_deps (tenant_id, child_group_id);

-- transitive closure of grp_deps (cycle veto, ancestors)
CREATE TABLE IF NOT EXISTS grp_closure (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  ancestor_id TEXT NOT NULL,
  descendant_id TEXT NOT NULL,
  -- number of distinct paths, for maintenance on delete
  paths INTEGER NOT NULL,
  min_depth INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, ancestor_id, descendant_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS grp_closure_desc ON grp_closure (tenant_id, descendant_id);

-- longest path from a leaf; the engine processes ascending
CREATE TABLE IF NOT EXISTS grp_levels (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL REFERENCES grp_groups (id),
  level INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, group_id)
);

CREATE TABLE IF NOT EXISTS grp_effective (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  list_id TEXT NOT NULL,
  identity_id INTEGER NOT NULL,
  support INTEGER NOT NULL CHECK (support > 0),
  since TEXT NOT NULL,
  PRIMARY KEY (tenant_id, group_id, list_id, identity_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS grp_eff_identity ON grp_effective (tenant_id, identity_id, list_id, group_id);

-- work that did not fit the synchronous budget
CREATE TABLE IF NOT EXISTS grp_engine_queue (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  seq INTEGER NOT NULL,
  -- seed | recompute_group | rebuild_tenant
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  enqueued_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);

-- ---------------------------------------------------------------- cross-tenant guards

CREATE TRIGGER IF NOT EXISTS tg_grp_folders_xtenant_ins BEFORE INSERT ON grp_folders
WHEN NEW.parent_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.parent_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_folders'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_folders_xtenant_upd BEFORE UPDATE OF tenant_id, parent_id ON grp_folders
WHEN NEW.parent_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.parent_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_folders'); END;

-- object_id names a folder or a group by object_type, with no foreign key
CREATE TRIGGER IF NOT EXISTS tg_grp_name_aliases_xtenant_ins BEFORE INSERT ON grp_name_aliases
WHEN (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_name_aliases'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_name_aliases_xtenant_upd BEFORE UPDATE OF tenant_id, object_type, object_id ON grp_name_aliases
WHEN (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_name_aliases'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_groups_xtenant_ins BEFORE INSERT ON grp_groups
WHEN EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.folder_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_groups'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_groups_xtenant_upd BEFORE UPDATE OF tenant_id, folder_id ON grp_groups
WHEN EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.folder_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_groups'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_composite_factors_xtenant_ins BEFORE INSERT ON grp_composite_factors
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.factor_group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_composite_factors'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_composite_factors_xtenant_upd BEFORE UPDATE OF tenant_id, group_id, factor_group_id ON grp_composite_factors
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.factor_group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_composite_factors'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_direct_memberships_xtenant_ins BEFORE INSERT ON grp_direct_memberships
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_lists p WHERE p.id = NEW.list_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.member_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.member_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.member_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.member_group_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_direct_memberships'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_direct_memberships_xtenant_upd BEFORE UPDATE OF tenant_id, group_id, list_id, member_identity_id, member_group_id ON grp_direct_memberships
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_lists p WHERE p.id = NEW.list_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.member_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.member_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.member_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.member_group_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_direct_memberships'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_deps_xtenant_ins BEFORE INSERT ON grp_deps
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.parent_group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.child_group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_lists p WHERE p.id = NEW.list_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_deps'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_deps_xtenant_upd BEFORE UPDATE OF tenant_id, parent_group_id, child_group_id, list_id ON grp_deps
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.parent_group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.child_group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_lists p WHERE p.id = NEW.list_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_deps'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_levels_xtenant_ins BEFORE INSERT ON grp_levels
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_levels'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_levels_xtenant_upd BEFORE UPDATE OF tenant_id, group_id ON grp_levels
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_levels'); END;
