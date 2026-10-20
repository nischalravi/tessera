-- Attribute framework (issue #50, GR-7; design docs/design/groups-grouper-parity.md
-- §10.9, §3.5). The design numbers this file 0104; 0280..0285 are taken here and
-- 0286 belongs to another change, so it is 0287.
--
--   grp_attr_defs               attribute definitions; each lives in a folder and has
--                               the eight attr_* privileges (grp_privileges, 0285)
--   grp_attr_names              names under a definition
--   grp_attr_name_implies       closure of the name implication edges of a definition
--   grp_attr_actions            actions of a definition
--   grp_attr_action_implies     closure of the action implication edges
--   grp_attr_assigns            assignments on a folder, group, identity, direct
--                               membership, attribute definition or another assignment
--   grp_attr_values             typed values of an assignment
--
-- Tenant-owned like 0001_tenancy.sql: every table has tenant_id, every unique
-- constraint starts with it, and the guard triggers at the end refuse a
-- reference to another tenant's row. A definition's full name is its folder's
-- name, ':' and its extension (a name's is the definition's, ':' and its
-- extension); it is derived, not stored, so renaming or moving a folder needs no
-- rewrite here.
--
-- Floating values are never stored as REAL: value_string holds the decimal
-- text, so the audit hash and the event JSON stay float-free.

CREATE TABLE IF NOT EXISTS grp_attr_defs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  folder_id TEXT NOT NULL REFERENCES grp_folders (id),
  extension TEXT NOT NULL CHECK (length(extension) BETWEEN 1 AND 255 AND extension NOT GLOB '*[^A-Za-z0-9_.-]*'),
  display_extension TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  attr_type TEXT NOT NULL CHECK (attr_type IN ('attr','limit','perm','type','service')),
  value_type TEXT NOT NULL CHECK (value_type IN ('marker','string','integer','floating','timestamp','member_id')),
  multi_assign INTEGER NOT NULL DEFAULT 0 CHECK (multi_assign IN (0,1)),
  multi_valued INTEGER NOT NULL DEFAULT 0 CHECK (multi_valued IN (0,1)),
  -- JSON array of the owner types an assignment of this definition may sit on
  assign_to TEXT NOT NULL CHECK (json_valid(assign_to)),
  -- built in (the object types definition): it cannot be deleted or retyped
  system INTEGER NOT NULL DEFAULT 0 CHECK (system IN (0,1)),
  created_at TEXT NOT NULL,
  created_by TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, folder_id, extension),
  CHECK (value_type <> 'marker' OR multi_valued = 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS grp_attr_defs_ci ON grp_attr_defs (tenant_id, folder_id, lower(extension));

CREATE TABLE IF NOT EXISTS grp_attr_names (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL REFERENCES grp_attr_defs (id),
  extension TEXT NOT NULL CHECK (length(extension) BETWEEN 1 AND 255 AND extension NOT GLOB '*[^A-Za-z0-9_.-]*'),
  display_extension TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT,
  UNIQUE (tenant_id, def_id, extension)
);
CREATE UNIQUE INDEX IF NOT EXISTS grp_attr_names_ci ON grp_attr_names (tenant_id, def_id, lower(extension));

-- name_id implies implied_id (an assignment of the first is also one of the second).
-- direct = 1 rows are the edges a person set; the others are their transitive
-- closure, rebuilt by internal/groups/attrs after every change of the edges.
CREATE TABLE IF NOT EXISTS grp_attr_name_implies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL REFERENCES grp_attr_defs (id),
  name_id TEXT NOT NULL REFERENCES grp_attr_names (id),
  implied_id TEXT NOT NULL REFERENCES grp_attr_names (id),
  direct INTEGER NOT NULL CHECK (direct IN (0,1)),
  PRIMARY KEY (tenant_id, name_id, implied_id),
  CHECK (name_id <> implied_id)
);
CREATE INDEX IF NOT EXISTS grp_attr_name_implies_rev ON grp_attr_name_implies (tenant_id, implied_id);
CREATE INDEX IF NOT EXISTS grp_attr_name_implies_def ON grp_attr_name_implies (tenant_id, def_id);

CREATE TABLE IF NOT EXISTS grp_attr_actions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL REFERENCES grp_attr_defs (id),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64 AND name NOT GLOB '*[^A-Za-z0-9_.-]*'),
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, def_id, name)
);
CREATE UNIQUE INDEX IF NOT EXISTS grp_attr_actions_ci ON grp_attr_actions (tenant_id, def_id, lower(name));

CREATE TABLE IF NOT EXISTS grp_attr_action_implies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL REFERENCES grp_attr_defs (id),
  action_id TEXT NOT NULL REFERENCES grp_attr_actions (id),
  implied_id TEXT NOT NULL REFERENCES grp_attr_actions (id),
  direct INTEGER NOT NULL CHECK (direct IN (0,1)),
  PRIMARY KEY (tenant_id, action_id, implied_id),
  CHECK (action_id <> implied_id)
);
CREATE INDEX IF NOT EXISTS grp_attr_action_implies_rev ON grp_attr_action_implies (tenant_id, implied_id);
CREATE INDEX IF NOT EXISTS grp_attr_action_implies_def ON grp_attr_action_implies (tenant_id, def_id);

-- owner_id names the owner by owner_type, with no foreign key (the owner is of
-- several tables; an identity's id is an integer, kept here as its decimal
-- text), so the guard triggers check the tenant. An effective membership is
-- derived and read-only, so no row names one.
CREATE TABLE IF NOT EXISTS grp_attr_assigns (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL REFERENCES grp_attr_defs (id),
  name_id TEXT NOT NULL REFERENCES grp_attr_names (id),
  action_id TEXT NOT NULL REFERENCES grp_attr_actions (id),
  owner_type TEXT NOT NULL CHECK (owner_type IN ('folder','group','identity','membership','attr_def','assignment')),
  owner_id TEXT NOT NULL,
  disallowed INTEGER NOT NULL DEFAULT 0 CHECK (disallowed IN (0,1)),
  enabled_from TEXT,
  disabled_at TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  CHECK (enabled_from IS NULL OR disabled_at IS NULL OR disabled_at > enabled_from)
);
CREATE INDEX IF NOT EXISTS grp_attr_assigns_owner ON grp_attr_assigns (tenant_id, owner_type, owner_id);
CREATE INDEX IF NOT EXISTS grp_attr_assigns_name ON grp_attr_assigns (tenant_id, name_id);
CREATE INDEX IF NOT EXISTS grp_attr_assigns_def ON grp_attr_assigns (tenant_id, def_id);

CREATE TABLE IF NOT EXISTS grp_attr_values (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  assign_id TEXT NOT NULL REFERENCES grp_attr_assigns (id),
  value_string TEXT,
  value_integer INTEGER,
  value_timestamp TEXT,
  value_member_id INTEGER REFERENCES identities (id),
  -- the canonical text of the value: one value is stored once per assignment
  value_key TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, assign_id, value_key),
  CHECK ((value_string IS NOT NULL) + (value_integer IS NOT NULL) + (value_timestamp IS NOT NULL)
         + (value_member_id IS NOT NULL) = 1)
);
CREATE INDEX IF NOT EXISTS grp_attr_values_assign ON grp_attr_values (tenant_id, assign_id, position);
CREATE INDEX IF NOT EXISTS grp_attr_values_key ON grp_attr_values (tenant_id, value_key);

-- ---------------------------------------------------------------- cross-tenant guards

-- 0285 guards a privilege row's folder and group objects; an attribute
-- definition can be one from here on
CREATE TRIGGER IF NOT EXISTS tg_grp_privileges_xtenant_attrdef_ins BEFORE INSERT ON grp_privileges
WHEN NEW.object_type = 'attr_def' AND EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_privileges'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_privileges_xtenant_attrdef_upd BEFORE UPDATE OF tenant_id, object_type, object_id ON grp_privileges
WHEN NEW.object_type = 'attr_def' AND EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_privileges'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_defs_xtenant_ins BEFORE INSERT ON grp_attr_defs
WHEN EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.folder_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_defs'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_defs_xtenant_upd BEFORE UPDATE OF tenant_id, folder_id ON grp_attr_defs
WHEN EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.folder_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_defs'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_names_xtenant_ins BEFORE INSERT ON grp_attr_names
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_names'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_names_xtenant_upd BEFORE UPDATE OF tenant_id, def_id ON grp_attr_names
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_names'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_name_implies_xtenant_ins BEFORE INSERT ON grp_attr_name_implies
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_names p WHERE p.id = NEW.name_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_names p WHERE p.id = NEW.implied_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_name_implies'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_name_implies_xtenant_upd BEFORE UPDATE OF tenant_id, def_id, name_id, implied_id ON grp_attr_name_implies
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_names p WHERE p.id = NEW.name_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_names p WHERE p.id = NEW.implied_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_name_implies'); END;

-- both ends of an implication are names of the row's definition
CREATE TRIGGER IF NOT EXISTS tg_grp_attr_name_implies_same_def BEFORE INSERT ON grp_attr_name_implies
WHEN EXISTS (SELECT 1 FROM grp_attr_defs d WHERE d.id = NEW.def_id AND d.tenant_id = NEW.tenant_id)
	AND (EXISTS (SELECT 1 FROM grp_attr_names p WHERE p.id = NEW.name_id AND p.tenant_id = NEW.tenant_id AND p.def_id <> NEW.def_id)
	OR EXISTS (SELECT 1 FROM grp_attr_names p WHERE p.id = NEW.implied_id AND p.tenant_id = NEW.tenant_id AND p.def_id <> NEW.def_id))
BEGIN SELECT RAISE(ABORT, 'attribute names of one definition only: grp_attr_name_implies'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_actions_xtenant_ins BEFORE INSERT ON grp_attr_actions
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_actions'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_actions_xtenant_upd BEFORE UPDATE OF tenant_id, def_id ON grp_attr_actions
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_actions'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_action_implies_xtenant_ins BEFORE INSERT ON grp_attr_action_implies
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_actions p WHERE p.id = NEW.action_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_actions p WHERE p.id = NEW.implied_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_action_implies'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_action_implies_xtenant_upd BEFORE UPDATE OF tenant_id, def_id, action_id, implied_id ON grp_attr_action_implies
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_actions p WHERE p.id = NEW.action_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_actions p WHERE p.id = NEW.implied_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_action_implies'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_action_implies_same_def BEFORE INSERT ON grp_attr_action_implies
WHEN EXISTS (SELECT 1 FROM grp_attr_defs d WHERE d.id = NEW.def_id AND d.tenant_id = NEW.tenant_id)
	AND (EXISTS (SELECT 1 FROM grp_attr_actions p WHERE p.id = NEW.action_id AND p.tenant_id = NEW.tenant_id AND p.def_id <> NEW.def_id)
	OR EXISTS (SELECT 1 FROM grp_attr_actions p WHERE p.id = NEW.implied_id AND p.tenant_id = NEW.tenant_id AND p.def_id <> NEW.def_id))
BEGIN SELECT RAISE(ABORT, 'attribute actions of one definition only: grp_attr_action_implies'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_assigns_xtenant_ins BEFORE INSERT ON grp_attr_assigns
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_names p WHERE p.id = NEW.name_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_actions p WHERE p.id = NEW.action_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.owner_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'identity' AND EXISTS (SELECT 1 FROM identities p WHERE p.id = CAST(NEW.owner_id AS INTEGER) AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'membership' AND EXISTS (SELECT 1 FROM grp_direct_memberships p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'attr_def' AND EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'assignment' AND EXISTS (SELECT 1 FROM grp_attr_assigns p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_assigns'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_assigns_xtenant_upd BEFORE UPDATE OF tenant_id, def_id, name_id, action_id, owner_type, owner_id ON grp_attr_assigns
WHEN EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.def_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_names p WHERE p.id = NEW.name_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_attr_actions p WHERE p.id = NEW.action_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.owner_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'identity' AND EXISTS (SELECT 1 FROM identities p WHERE p.id = CAST(NEW.owner_id AS INTEGER) AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'membership' AND EXISTS (SELECT 1 FROM grp_direct_memberships p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'attr_def' AND EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_type = 'assignment' AND EXISTS (SELECT 1 FROM grp_attr_assigns p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_assigns'); END;

-- the name and the action of an assignment belong to its definition
CREATE TRIGGER IF NOT EXISTS tg_grp_attr_assigns_same_def BEFORE INSERT ON grp_attr_assigns
WHEN EXISTS (SELECT 1 FROM grp_attr_defs d WHERE d.id = NEW.def_id AND d.tenant_id = NEW.tenant_id)
	AND (EXISTS (SELECT 1 FROM grp_attr_names p WHERE p.id = NEW.name_id AND p.tenant_id = NEW.tenant_id AND p.def_id <> NEW.def_id)
	OR EXISTS (SELECT 1 FROM grp_attr_actions p WHERE p.id = NEW.action_id AND p.tenant_id = NEW.tenant_id AND p.def_id <> NEW.def_id))
BEGIN SELECT RAISE(ABORT, 'attribute name and action of the definition only: grp_attr_assigns'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_values_xtenant_ins BEFORE INSERT ON grp_attr_values
WHEN EXISTS (SELECT 1 FROM grp_attr_assigns p WHERE p.id = NEW.assign_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.value_member_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.value_member_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_values'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_attr_values_xtenant_upd BEFORE UPDATE OF tenant_id, assign_id, value_member_id ON grp_attr_values
WHEN EXISTS (SELECT 1 FROM grp_attr_assigns p WHERE p.id = NEW.assign_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.value_member_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.value_member_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_attr_values'); END;
