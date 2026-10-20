-- Postgres dialect of schema/0378_group_prov.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The cross-tenant triggers become composite foreign keys
-- (tenant_id, x_id) -> (tenant_id, id); grp_provisionable.object_id names a folder or a group by
-- object_type, so tessera_guard_grp_object (0285_group_events.sql) checks it. secret_enc is BYTEA and
-- json_valid is IS JSON.

-- +goose Up

CREATE TABLE grp_provisioners (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  target_type TEXT NOT NULL CHECK (target_type IN ('ldap','ad','scim2','sql','webhook')),
  connection_id TEXT,
  config TEXT NOT NULL CHECK (config IS JSON),
  secret_enc BYTEA,
  mode TEXT NOT NULL DEFAULT 'adopt' CHECK (mode IN ('adopt','dry_run','active','paused')),
  full_schedule TEXT NOT NULL DEFAULT '0 2 * * *',
  failsafe TEXT NOT NULL CHECK (failsafe IS JSON),
  needs_full INTEGER NOT NULL DEFAULT 1 CHECK (needs_full IN (0,1)),
  approve_next INTEGER NOT NULL DEFAULT 0 CHECK (approve_next IN (0,1)),
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);

CREATE TABLE grp_provisionable (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provisioner_id TEXT NOT NULL,
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group')),
  object_id TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'self' CHECK (scope IN ('self','one','sub')),
  include INTEGER NOT NULL DEFAULT 1 CHECK (include IN (0,1)),
  metadata TEXT NOT NULL DEFAULT '{}' CHECK (metadata IS JSON),
  PRIMARY KEY (tenant_id, provisioner_id, object_type, object_id),
  CHECK ((object_type = 'group') = (scope = 'self')),
  FOREIGN KEY (tenant_id, provisioner_id) REFERENCES grp_provisioners (tenant_id, id)
);

CREATE TABLE grp_sync_groups (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provisioner_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  target_id TEXT,
  target_name TEXT,
  state_hash TEXT,
  change_token TEXT,
  state_cache TEXT CHECK (state_cache IS NULL OR state_cache IS JSON),
  last_read_at TEXT,
  last_verified_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('adopted','synced','drift','failed','removed')),
  PRIMARY KEY (tenant_id, provisioner_id, group_id),
  FOREIGN KEY (tenant_id, provisioner_id) REFERENCES grp_provisioners (tenant_id, id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES grp_groups (tenant_id, id)
);
CREATE INDEX grp_sync_groups_name ON grp_sync_groups (tenant_id, provisioner_id, target_name);

CREATE TABLE grp_sync_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provisioner_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('full','incremental')),
  mode TEXT NOT NULL CHECK (mode IN ('adopt','dry_run','active')),
  status TEXT NOT NULL CHECK (status IN ('running','done','held','failed')),
  from_seq BIGINT NOT NULL DEFAULT 0,
  to_seq BIGINT NOT NULL DEFAULT 0,
  summary TEXT NOT NULL DEFAULT '{}' CHECK (summary IS JSON),
  error TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, provisioner_id) REFERENCES grp_provisioners (tenant_id, id)
);
CREATE INDEX grp_sync_runs_prov ON grp_sync_runs (tenant_id, provisioner_id, started_at);

CREATE TABLE grp_sync_ops (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provisioner_id TEXT NOT NULL,
  run_id TEXT,
  op TEXT NOT NULL CHECK (op IN ('create','update','members','delete')),
  object_ref TEXT NOT NULL,
  group_id TEXT,
  payload_hash TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}' CHECK (detail IS JSON),
  cause_seq BIGINT,
  status TEXT NOT NULL CHECK (status IN ('planned','applied','verified','failed','drift','skipped')),
  attempts INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  planned_at TEXT NOT NULL,
  applied_at TEXT,
  verified_at TEXT,
  FOREIGN KEY (tenant_id, provisioner_id) REFERENCES grp_provisioners (tenant_id, id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES grp_sync_runs (tenant_id, id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES grp_groups (tenant_id, id)
);
CREATE INDEX grp_sync_ops_prov ON grp_sync_ops (tenant_id, provisioner_id, planned_at);
CREATE INDEX grp_sync_ops_run ON grp_sync_ops (tenant_id, run_id);

CREATE TRIGGER tg_grp_provisionable_object_xtenant BEFORE INSERT OR UPDATE OF tenant_id, object_type, object_id ON grp_provisionable
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_grp_object();
