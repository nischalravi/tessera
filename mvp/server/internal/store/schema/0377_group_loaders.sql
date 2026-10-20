-- Group loaders (issue #53, GR-10; design docs/design/groups-grouper-parity.md
-- §9.1). The design numbers this file 0105; 0280..0286 are taken here and up to
-- 0292 are reserved, so it is 0293; renumbered 0377 in merge train 5 so it follows 0342_breakglass.sql (it widens a CHECK that file sets).
--
-- A loader fills native groups from a source (a SQL query, a CSV file, a
-- connector's groups, an identity attribute, group history). grp_loaders is
-- its definition, grp_loader_runs the history of its runs (a run that trips a
-- failsafe is 'held' and keeps the plan it computed until a person approves or
-- rejects it) and grp_loader_unresolved the subjects a source named that match
-- no identity yet: they are listed, counted in the failsafe and retried on
-- every run, never silently dropped.
--
-- secret_enc is the loader's credential (a bearer token for a CSV URL), sealed
-- with internal/seal; it is never returned by the API. config holds no secret.
--
-- Tenant-owned like every table of 0001_tenancy.sql: tenant_id references
-- tenants(id), every unique constraint starts with it, and the guard triggers
-- at the end refuse a reference to another tenant's row.

CREATE TABLE IF NOT EXISTS grp_loaders (
  id               TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL REFERENCES tenants (id),
  name             TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  -- validated by internal/groups/loaders: the set grows without a migration
  type             TEXT NOT NULL CHECK (length(type) BETWEEN 1 AND 64),
  connection_id    TEXT REFERENCES connections (id),
  config           TEXT NOT NULL CHECK (json_valid(config)),
  secret_enc       BLOB,
  target_folder_id TEXT NOT NULL REFERENCES grp_folders (id),
  name_template    TEXT NOT NULL DEFAULT '{{.Name}}' CHECK (length(name_template) BETWEEN 1 AND 255),
  on_missing_group TEXT NOT NULL DEFAULT 'empty' CHECK (on_missing_group IN ('empty','disable','delete','keep')),
  -- only keep subjects who are also effective members of this group (G-60)
  and_group_id     TEXT REFERENCES grp_groups (id),
  schedule         TEXT NOT NULL CHECK (length(schedule) BETWEEN 1 AND 255),
  incremental_secs INTEGER CHECK (incremental_secs IS NULL OR incremental_secs BETWEEN 30 AND 86400),
  failsafe         TEXT NOT NULL CHECK (json_valid(failsafe)),
  status           TEXT NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled','disabled','held')),
  -- the source's incremental cursor, advanced only when a run applied
  cursor           TEXT,
  last_full_at     TEXT,
  last_incremental_at TEXT,
  created_by       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  version          INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, name)
);
CREATE UNIQUE INDEX IF NOT EXISTS grp_loaders_ci ON grp_loaders (tenant_id, lower(name));
CREATE INDEX IF NOT EXISTS grp_loaders_folder ON grp_loaders (tenant_id, target_folder_id);

CREATE TABLE IF NOT EXISTS grp_loader_runs (
  id               TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL REFERENCES tenants (id),
  loader_id        TEXT NOT NULL REFERENCES grp_loaders (id),
  kind             TEXT NOT NULL CHECK (kind IN ('full','incremental','preview')),
  started_at       TEXT NOT NULL,
  finished_at      TEXT,
  -- previewed: a preview run (nothing was applied); the design's five statuses plus it
  status           TEXT NOT NULL CHECK (status IN ('running','applied','held','failed','approved','rejected','previewed')),
  source_rows      INTEGER,
  groups_seen      INTEGER,
  adds             INTEGER,
  removes          INTEGER,
  unresolved       INTEGER,
  failsafe_tripped TEXT,
  -- JSON downstream impact (K7), and the plan the run computed (applied by an approval as it is)
  impact           TEXT CHECK (impact IS NULL OR json_valid(impact)),
  plan             TEXT CHECK (plan IS NULL OR json_valid(plan)),
  source_hash      TEXT,
  error            TEXT,
  cursor_after     TEXT,
  requested_by     TEXT,
  decided_by       TEXT,
  decided_at       TEXT
);
CREATE INDEX IF NOT EXISTS grp_loader_runs_loader ON grp_loader_runs (tenant_id, loader_id, started_at);
CREATE INDEX IF NOT EXISTS grp_loader_runs_status ON grp_loader_runs (tenant_id, status);

CREATE TABLE IF NOT EXISTS grp_loader_unresolved (
  tenant_id  TEXT NOT NULL REFERENCES tenants (id),
  loader_id  TEXT NOT NULL REFERENCES grp_loaders (id),
  source     TEXT NOT NULL,
  identifier TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  -- JSON list of the group names the subject was listed in
  groups     TEXT NOT NULL CHECK (json_valid(groups)),
  PRIMARY KEY (tenant_id, loader_id, source, identifier)
);

-- ---------------------------------------------------------------- cross-tenant guards

CREATE TRIGGER IF NOT EXISTS tg_grp_loaders_xtenant_ins BEFORE INSERT ON grp_loaders
WHEN EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.target_folder_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.and_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.and_group_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_loaders'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_loaders_xtenant_upd BEFORE UPDATE OF tenant_id, target_folder_id, and_group_id, connection_id ON grp_loaders
WHEN EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.target_folder_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.and_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.and_group_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_loaders'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_loader_runs_xtenant_ins BEFORE INSERT ON grp_loader_runs
WHEN EXISTS (SELECT 1 FROM grp_loaders p WHERE p.id = NEW.loader_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_loader_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_loader_runs_xtenant_upd BEFORE UPDATE OF tenant_id, loader_id ON grp_loader_runs
WHEN EXISTS (SELECT 1 FROM grp_loaders p WHERE p.id = NEW.loader_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_loader_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_loader_unresolved_xtenant_ins BEFORE INSERT ON grp_loader_unresolved
WHEN EXISTS (SELECT 1 FROM grp_loaders p WHERE p.id = NEW.loader_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_loader_unresolved'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_loader_unresolved_xtenant_upd BEFORE UPDATE OF tenant_id, loader_id ON grp_loader_unresolved
WHEN EXISTS (SELECT 1 FROM grp_loaders p WHERE p.id = NEW.loader_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_loader_unresolved'); END;
