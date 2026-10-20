-- Postgres dialect of schema/0287_group_attrs.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The foreign keys are composite (tenant_id, x_id) ->
-- (tenant_id, id) and replace the SQLite cross-tenant triggers; "a name and an action of the
-- definition only" is enforced by composite keys that carry def_id. The owner of an assignment is
-- polymorphic (owner_type, owner_id), so a plpgsql guard checks its tenant. json_valid is dropped:
-- assign_to is TEXT and internal/groups/attrs validates it. The privilege object guard of 0285 gains
-- the attr_def object type.

-- +goose Up

CREATE TABLE grp_attr_defs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  folder_id TEXT NOT NULL,
  extension TEXT NOT NULL CHECK (length(extension) BETWEEN 1 AND 255 AND extension !~ '[^A-Za-z0-9_.-]'),
  display_extension TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  attr_type TEXT NOT NULL CHECK (attr_type IN ('attr','limit','perm','type','service')),
  value_type TEXT NOT NULL CHECK (value_type IN ('marker','string','integer','floating','timestamp','member_id')),
  multi_assign INTEGER NOT NULL DEFAULT 0 CHECK (multi_assign IN (0,1)),
  multi_valued INTEGER NOT NULL DEFAULT 0 CHECK (multi_valued IN (0,1)),
  assign_to TEXT NOT NULL,
  system INTEGER NOT NULL DEFAULT 0 CHECK (system IN (0,1)),
  created_at TEXT NOT NULL,
  created_by TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, folder_id, extension),
  CHECK (value_type <> 'marker' OR multi_valued = 0),
  FOREIGN KEY (tenant_id, folder_id) REFERENCES grp_folders (tenant_id, id)
);
CREATE UNIQUE INDEX grp_attr_defs_ci ON grp_attr_defs (tenant_id, folder_id, lower(extension));

CREATE TABLE grp_attr_names (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL,
  extension TEXT NOT NULL CHECK (length(extension) BETWEEN 1 AND 255 AND extension !~ '[^A-Za-z0-9_.-]'),
  display_extension TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, def_id, id),
  UNIQUE (tenant_id, def_id, extension),
  FOREIGN KEY (tenant_id, def_id) REFERENCES grp_attr_defs (tenant_id, id)
);
CREATE UNIQUE INDEX grp_attr_names_ci ON grp_attr_names (tenant_id, def_id, lower(extension));

CREATE TABLE grp_attr_name_implies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL,
  name_id TEXT NOT NULL,
  implied_id TEXT NOT NULL,
  direct INTEGER NOT NULL CHECK (direct IN (0,1)),
  PRIMARY KEY (tenant_id, name_id, implied_id),
  CHECK (name_id <> implied_id),
  FOREIGN KEY (tenant_id, def_id) REFERENCES grp_attr_defs (tenant_id, id),
  FOREIGN KEY (tenant_id, def_id, name_id) REFERENCES grp_attr_names (tenant_id, def_id, id),
  FOREIGN KEY (tenant_id, def_id, implied_id) REFERENCES grp_attr_names (tenant_id, def_id, id)
);
CREATE INDEX grp_attr_name_implies_rev ON grp_attr_name_implies (tenant_id, implied_id);
CREATE INDEX grp_attr_name_implies_def ON grp_attr_name_implies (tenant_id, def_id);

CREATE TABLE grp_attr_actions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64 AND name !~ '[^A-Za-z0-9_.-]'),
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, def_id, id),
  UNIQUE (tenant_id, def_id, name),
  FOREIGN KEY (tenant_id, def_id) REFERENCES grp_attr_defs (tenant_id, id)
);
CREATE UNIQUE INDEX grp_attr_actions_ci ON grp_attr_actions (tenant_id, def_id, lower(name));

CREATE TABLE grp_attr_action_implies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  implied_id TEXT NOT NULL,
  direct INTEGER NOT NULL CHECK (direct IN (0,1)),
  PRIMARY KEY (tenant_id, action_id, implied_id),
  CHECK (action_id <> implied_id),
  FOREIGN KEY (tenant_id, def_id) REFERENCES grp_attr_defs (tenant_id, id),
  FOREIGN KEY (tenant_id, def_id, action_id) REFERENCES grp_attr_actions (tenant_id, def_id, id),
  FOREIGN KEY (tenant_id, def_id, implied_id) REFERENCES grp_attr_actions (tenant_id, def_id, id)
);
CREATE INDEX grp_attr_action_implies_rev ON grp_attr_action_implies (tenant_id, implied_id);
CREATE INDEX grp_attr_action_implies_def ON grp_attr_action_implies (tenant_id, def_id);

CREATE TABLE grp_attr_assigns (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  def_id TEXT NOT NULL,
  name_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  owner_type TEXT NOT NULL CHECK (owner_type IN ('folder','group','identity','membership','attr_def','assignment')),
  owner_id TEXT NOT NULL,
  disallowed INTEGER NOT NULL DEFAULT 0 CHECK (disallowed IN (0,1)),
  enabled_from TEXT,
  disabled_at TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, id),
  CHECK (enabled_from IS NULL OR disabled_at IS NULL OR disabled_at > enabled_from),
  FOREIGN KEY (tenant_id, def_id) REFERENCES grp_attr_defs (tenant_id, id),
  FOREIGN KEY (tenant_id, def_id, name_id) REFERENCES grp_attr_names (tenant_id, def_id, id),
  FOREIGN KEY (tenant_id, def_id, action_id) REFERENCES grp_attr_actions (tenant_id, def_id, id)
);
CREATE INDEX grp_attr_assigns_owner ON grp_attr_assigns (tenant_id, owner_type, owner_id);
CREATE INDEX grp_attr_assigns_name ON grp_attr_assigns (tenant_id, name_id);
CREATE INDEX grp_attr_assigns_def ON grp_attr_assigns (tenant_id, def_id);

CREATE TABLE grp_attr_values (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  assign_id TEXT NOT NULL,
  value_string TEXT,
  value_integer BIGINT,
  value_timestamp TEXT,
  value_member_id BIGINT,
  value_key TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, assign_id, value_key),
  CHECK ((value_string IS NOT NULL)::int + (value_integer IS NOT NULL)::int + (value_timestamp IS NOT NULL)::int
         + (value_member_id IS NOT NULL)::int = 1),
  FOREIGN KEY (tenant_id, assign_id) REFERENCES grp_attr_assigns (tenant_id, id),
  FOREIGN KEY (tenant_id, value_member_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX grp_attr_values_assign ON grp_attr_values (tenant_id, assign_id, position);
CREATE INDEX grp_attr_values_key ON grp_attr_values (tenant_id, value_key);

-- ---------------------------------------------------------------- cross-tenant guards

-- 0285's guard of a privilege row's object gains the attribute definition
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_grp_object() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
	crosses boolean := false;
BEGIN
	IF NEW.object_type = 'folder' THEN
		SELECT EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.object_type = 'group' THEN
		SELECT EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.object_type = 'attr_def' THEN
		SELECT EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	END IF;
	IF crosses THEN
		RAISE EXCEPTION 'cross-tenant reference: %', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

-- the owner of an assignment is named by owner_type (no foreign key)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_grp_attr_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
	crosses boolean := false;
BEGIN
	IF NEW.owner_type = 'folder' THEN
		SELECT EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.owner_type = 'group' THEN
		SELECT EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.owner_type = 'identity' THEN
		SELECT EXISTS (SELECT 1 FROM identities p WHERE p.id::text = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.owner_type = 'membership' THEN
		SELECT EXISTS (SELECT 1 FROM grp_direct_memberships p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.owner_type = 'attr_def' THEN
		SELECT EXISTS (SELECT 1 FROM grp_attr_defs p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSIF NEW.owner_type = 'assignment' THEN
		SELECT EXISTS (SELECT 1 FROM grp_attr_assigns p WHERE p.id = NEW.owner_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	END IF;
	IF crosses THEN
		RAISE EXCEPTION 'cross-tenant reference: %', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

CREATE TRIGGER tg_grp_attr_assigns_owner_xtenant BEFORE INSERT OR UPDATE OF tenant_id, owner_type, owner_id ON grp_attr_assigns
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_grp_attr_owner();

-- a BEFORE trigger refuses a definition of another tenant before the primary key is checked, like SQLite
CREATE TRIGGER tg_grp_attr_name_implies_def_xtenant BEFORE INSERT OR UPDATE OF tenant_id, def_id ON grp_attr_name_implies
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_attr_defs', 'def_id', 'text');
CREATE TRIGGER tg_grp_attr_action_implies_def_xtenant BEFORE INSERT OR UPDATE OF tenant_id, def_id ON grp_attr_action_implies
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_attr_defs', 'def_id', 'text');
