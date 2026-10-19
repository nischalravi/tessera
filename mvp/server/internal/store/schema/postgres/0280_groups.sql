-- Postgres dialect of schema/0280_groups.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE grp_folders (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  parent_id TEXT,
  extension TEXT NOT NULL CHECK (length(extension) BETWEEN 0 AND 255
    AND (extension = '' OR extension !~ '[^A-Za-z0-9_.-]')),
  display_extension TEXT NOT NULL,
  name TEXT NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  id_index BIGINT NOT NULL,
  object_types TEXT NOT NULL DEFAULT '[]',
  data_owner TEXT,
  managed_by TEXT NOT NULL DEFAULT 'ui'
    CHECK (managed_by IN ('ui','policy_repo','loader','grouper_mirror','connector')),
  external_ref TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT,
  version BIGINT NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id_index),
  CHECK ((parent_id IS NULL) = (extension = '')),
  FOREIGN KEY (tenant_id, parent_id) REFERENCES grp_folders (tenant_id, id)
);

CREATE UNIQUE INDEX grp_folders_ci ON grp_folders (tenant_id, lower(name));
CREATE UNIQUE INDEX grp_folders_root ON grp_folders (tenant_id) WHERE parent_id IS NULL;
CREATE INDEX grp_folders_parent ON grp_folders (tenant_id, parent_id);

CREATE TABLE grp_name_aliases (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group')),
  object_id TEXT NOT NULL,
  old_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, object_type, old_name)
);

CREATE UNIQUE INDEX grp_name_aliases_ci ON grp_name_aliases (tenant_id, lower(old_name));
CREATE INDEX grp_name_aliases_object ON grp_name_aliases (tenant_id, object_type, object_id);

CREATE TABLE grp_groups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  folder_id TEXT NOT NULL,
  extension TEXT NOT NULL CHECK (length(extension) BETWEEN 1 AND 255 AND extension !~ '[^A-Za-z0-9_.-]'),
  display_extension TEXT NOT NULL,
  name TEXT NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  id_index BIGINT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'group' CHECK (kind IN ('group','role')),
  definition TEXT NOT NULL DEFAULT 'basic' CHECK (definition IN ('basic','composite','policy')),
  composite_op TEXT CHECK (composite_op IN ('union','intersection','complement')),
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
  requestable BIGINT NOT NULL DEFAULT 0,
  effective_count BIGINT NOT NULL DEFAULT 0,
  effective_version BIGINT NOT NULL DEFAULT 0,
  recompute_state TEXT NOT NULL DEFAULT 'clean' CHECK (recompute_state IN ('clean','pending','failed')),
  external_ref TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT,
  version BIGINT NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id_index),
  CHECK ((definition = 'composite') = (composite_op IS NOT NULL)),
  CHECK ((definition = 'policy') = (policy_ref IS NOT NULL)),
  FOREIGN KEY (tenant_id, folder_id) REFERENCES grp_folders (tenant_id, id)
);

CREATE UNIQUE INDEX grp_groups_ci ON grp_groups (tenant_id, lower(name));
CREATE INDEX grp_groups_folder ON grp_groups (tenant_id, folder_id);

CREATE TABLE grp_composite_factors (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  position BIGINT NOT NULL,
  factor_group_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, group_id, position),
  FOREIGN KEY (tenant_id, group_id) REFERENCES grp_groups (tenant_id, id),
  FOREIGN KEY (tenant_id, factor_group_id) REFERENCES grp_groups (tenant_id, id)
);

CREATE TABLE grp_lists (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  read_priv TEXT NOT NULL DEFAULT 'read',
  write_priv TEXT NOT NULL DEFAULT 'update',
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name)
);

CREATE TABLE grp_direct_memberships (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  list_id TEXT NOT NULL,
  member_type TEXT NOT NULL CHECK (member_type IN ('identity','group')),
  member_identity_id BIGINT,
  member_group_id TEXT,
  enabled_from TEXT,
  disabled_at TEXT,
  source TEXT NOT NULL,
  source_ref TEXT,
  reason TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  CHECK ((member_type = 'identity') = (member_identity_id IS NOT NULL)),
  CHECK ((member_type = 'group') = (member_group_id IS NOT NULL)),
  CHECK (disabled_at IS NULL OR enabled_from IS NULL OR disabled_at > enabled_from),
  FOREIGN KEY (tenant_id, group_id) REFERENCES grp_groups (tenant_id, id),
  FOREIGN KEY (tenant_id, list_id) REFERENCES grp_lists (tenant_id, id),
  FOREIGN KEY (tenant_id, member_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, member_group_id) REFERENCES grp_groups (tenant_id, id)
);

CREATE UNIQUE INDEX grp_dm_ident ON grp_direct_memberships (tenant_id, group_id, list_id, member_identity_id)
  WHERE member_type = 'identity';
CREATE UNIQUE INDEX grp_dm_group ON grp_direct_memberships (tenant_id, group_id, list_id, member_group_id)
  WHERE member_type = 'group';
CREATE INDEX grp_dm_by_identity ON grp_direct_memberships (tenant_id, member_identity_id);
CREATE INDEX grp_dm_enable ON grp_direct_memberships (tenant_id, enabled_from) WHERE enabled_from IS NOT NULL;
CREATE INDEX grp_dm_disable ON grp_direct_memberships (tenant_id, disabled_at) WHERE disabled_at IS NOT NULL;

CREATE TABLE grp_deps (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  parent_group_id TEXT NOT NULL,
  child_group_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('nest','factor')),
  list_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, parent_group_id, child_group_id, kind, list_id),
  FOREIGN KEY (tenant_id, parent_group_id) REFERENCES grp_groups (tenant_id, id),
  FOREIGN KEY (tenant_id, child_group_id) REFERENCES grp_groups (tenant_id, id),
  FOREIGN KEY (tenant_id, list_id) REFERENCES grp_lists (tenant_id, id)
);

CREATE INDEX grp_deps_child ON grp_deps (tenant_id, child_group_id);

CREATE TABLE grp_closure (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  ancestor_id TEXT NOT NULL,
  descendant_id TEXT NOT NULL,
  paths BIGINT NOT NULL,
  min_depth BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, ancestor_id, descendant_id)
);

CREATE INDEX grp_closure_desc ON grp_closure (tenant_id, descendant_id);

CREATE TABLE grp_levels (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  level BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, group_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES grp_groups (tenant_id, id)
);

CREATE TABLE grp_effective (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  list_id TEXT NOT NULL,
  identity_id BIGINT NOT NULL,
  support BIGINT NOT NULL CHECK (support > 0),
  since TEXT NOT NULL,
  PRIMARY KEY (tenant_id, group_id, list_id, identity_id)
);

CREATE INDEX grp_eff_identity ON grp_effective (tenant_id, identity_id, list_id, group_id);

CREATE TABLE grp_engine_queue (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  seq BIGINT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  enqueued_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);

-- object_id names a folder or a group by object_type, with no foreign key. The guard
-- refuses an id that belongs to ANOTHER tenant and tolerates one that does not exist, like the
-- SQLite triggers. SECURITY DEFINER for the same reason as tessera_guard_soft_ref (0001_tenancy.sql).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_grp_alias() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
	crosses boolean;
BEGIN
	IF NEW.object_type = 'folder' THEN
		SELECT EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	ELSE
		SELECT EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id) INTO crosses;
	END IF;
	IF crosses THEN
		RAISE EXCEPTION 'cross-tenant reference: grp_name_aliases' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

CREATE TRIGGER tg_grp_name_aliases_xtenant BEFORE INSERT OR UPDATE OF tenant_id, object_type, object_id ON grp_name_aliases
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_grp_alias();
