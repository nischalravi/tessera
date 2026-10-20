-- Postgres dialect of schema/0377_group_loaders.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The cross-tenant triggers become composite foreign keys
-- (tenant_id, x_id) -> (tenant_id, id); secret_enc is BYTEA; json_valid is IS JSON.
--
-- It also widens the admin_change_requests type CHECK to admit groups.loader.save (numbered after 0342_breakglass.sql, which sets the same CHECK; SQLite changes the
-- CHECK in 0008_admin_changes.sql, as breakglass did; see 0342_breakglass.sql).

-- +goose Up

ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke','groups.loader.save'));

CREATE TABLE grp_loaders (
  id               TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL REFERENCES tenants (id),
  name             TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  type             TEXT NOT NULL CHECK (length(type) BETWEEN 1 AND 64),
  connection_id    TEXT,
  config           TEXT NOT NULL CHECK (config IS JSON),
  secret_enc       BYTEA,
  target_folder_id TEXT NOT NULL,
  name_template    TEXT NOT NULL DEFAULT '{{.Name}}' CHECK (length(name_template) BETWEEN 1 AND 255),
  on_missing_group TEXT NOT NULL DEFAULT 'empty' CHECK (on_missing_group IN ('empty','disable','delete','keep')),
  and_group_id     TEXT,
  schedule         TEXT NOT NULL CHECK (length(schedule) BETWEEN 1 AND 255),
  incremental_secs INTEGER CHECK (incremental_secs IS NULL OR incremental_secs BETWEEN 30 AND 86400),
  failsafe         TEXT NOT NULL CHECK (failsafe IS JSON),
  status           TEXT NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled','disabled','held')),
  cursor           TEXT,
  last_full_at     TEXT,
  last_incremental_at TEXT,
  created_by       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  version          INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  FOREIGN KEY (tenant_id, target_folder_id) REFERENCES grp_folders (tenant_id, id),
  FOREIGN KEY (tenant_id, and_group_id) REFERENCES grp_groups (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
CREATE UNIQUE INDEX grp_loaders_ci ON grp_loaders (tenant_id, lower(name));
CREATE INDEX grp_loaders_folder ON grp_loaders (tenant_id, target_folder_id);

CREATE TABLE grp_loader_runs (
  id               TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL REFERENCES tenants (id),
  loader_id        TEXT NOT NULL,
  kind             TEXT NOT NULL CHECK (kind IN ('full','incremental','preview')),
  started_at       TEXT NOT NULL,
  finished_at      TEXT,
  status           TEXT NOT NULL CHECK (status IN ('running','applied','held','failed','approved','rejected','previewed')),
  source_rows      INTEGER,
  groups_seen      INTEGER,
  adds             INTEGER,
  removes          INTEGER,
  unresolved       INTEGER,
  failsafe_tripped TEXT,
  impact           TEXT CHECK (impact IS NULL OR impact IS JSON),
  plan             TEXT CHECK (plan IS NULL OR plan IS JSON),
  source_hash      TEXT,
  error            TEXT,
  cursor_after     TEXT,
  requested_by     TEXT,
  decided_by       TEXT,
  decided_at       TEXT,
  FOREIGN KEY (tenant_id, loader_id) REFERENCES grp_loaders (tenant_id, id)
);
CREATE INDEX grp_loader_runs_loader ON grp_loader_runs (tenant_id, loader_id, started_at);
CREATE INDEX grp_loader_runs_status ON grp_loader_runs (tenant_id, status);

CREATE TABLE grp_loader_unresolved (
  tenant_id  TEXT NOT NULL REFERENCES tenants (id),
  loader_id  TEXT NOT NULL,
  source     TEXT NOT NULL,
  identifier TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  groups     TEXT NOT NULL CHECK (groups IS JSON),
  PRIMARY KEY (tenant_id, loader_id, source, identifier),
  FOREIGN KEY (tenant_id, loader_id) REFERENCES grp_loaders (tenant_id, id)
);
