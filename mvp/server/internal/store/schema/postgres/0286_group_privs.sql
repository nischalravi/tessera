-- Postgres dialect of schema/0286_group_privs.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The holder cross-tenant guards become composite foreign keys
-- (tenant_id, x_id) -> (tenant_id, id); object_id names a folder or group with no foreign key, so
-- tessera_guard_grp_object (0285_group_events.sql) checks it. json_valid is dropped: body is TEXT
-- and internal/groups/privs validates it.

-- +goose Up

CREATE TABLE grp_privileges (
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
  holder_identity_id BIGINT,
  holder_group_id    TEXT,
  applies_to         TEXT NOT NULL DEFAULT 'self'
                     CHECK (applies_to IN ('self','groups','folders','attr_defs')),
  scope              TEXT NOT NULL DEFAULT 'self' CHECK (scope IN ('self','one','sub')),
  source             TEXT NOT NULL CHECK (source IN ('ui','api','creator_default','grouper_import','template')),
  created_by         TEXT,
  created_at         TEXT NOT NULL,
  CHECK ((applies_to = 'self') = (scope = 'self')),
  CHECK (applies_to = 'self' OR object_type = 'folder'),
  CHECK ((holder_type = 'identity') = (holder_identity_id IS NOT NULL)),
  CHECK ((holder_type = 'group') = (holder_group_id IS NOT NULL)),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, holder_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, holder_group_id) REFERENCES grp_groups (tenant_id, id)
);
CREATE INDEX grp_priv_object ON grp_privileges (tenant_id, object_type, object_id);
CREATE INDEX grp_priv_holder_g ON grp_privileges (tenant_id, holder_group_id);
CREATE INDEX grp_priv_holder_i ON grp_privileges (tenant_id, holder_identity_id);

-- a grant is made once: one partial unique index per kind of holder
CREATE UNIQUE INDEX grp_priv_once_identity ON grp_privileges
  (tenant_id, object_type, object_id, privilege, applies_to, scope, holder_identity_id) WHERE holder_type = 'identity';
CREATE UNIQUE INDEX grp_priv_once_group ON grp_privileges
  (tenant_id, object_type, object_id, privilege, applies_to, scope, holder_group_id) WHERE holder_type = 'group';
CREATE UNIQUE INDEX grp_priv_once_everyone ON grp_privileges
  (tenant_id, object_type, object_id, privilege, applies_to, scope) WHERE holder_type = 'everyone';

-- Groups privilege settings, one row per tenant (Admin > Groups settings, §7.2,
-- G-40): the privileges that may be granted to everyone, and the grants made to
-- everyone on every new object. body is JSON, validated by internal/groups/privs.
CREATE TABLE grp_priv_settings (
  tenant_id  TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  body       TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT
);

CREATE TRIGGER tg_grp_privileges_object_xtenant BEFORE INSERT OR UPDATE OF tenant_id, object_type, object_id ON grp_privileges
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_grp_object();
