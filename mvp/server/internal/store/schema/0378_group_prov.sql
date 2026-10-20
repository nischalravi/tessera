-- Group provisioning (issue #54, GR-11; design docs/design/groups-grouper-parity.md
-- §9.2 "0106_group_prov"). The design numbers this file 0106; the repo's
-- native-groups files are 0280..0282 (GR-1..GR-3), so it is 0378 here.
--
-- A provisioner pushes the effective membership of marked groups to one target
-- system (LDAP, Active Directory, SCIM 2.0, a SQL table, a webhook).
--
--   grp_provisioners   one target: type, non-secret config, the sealed secret
--                      (internal/seal, AAD bound to tenant, table, column and
--                      row), mode, schedule and failsafe limits
--   grp_provisionable  marks: a group, or a folder (scope one|sub, dynamic
--                      inheritance: never copied onto the groups below it);
--                      include = 0 opts a group or a subtree out of a mark above
--   grp_sync_groups    what the provisioner owns on the target, and the cache of
--                      the last-read target state (sync-back, G-69)
--   grp_sync_runs      one full or incremental run, with its summary
--   grp_sync_ops       one planned change on the target and how far it got:
--                      planned -> applied -> verified (only after a targeted
--                      re-read), or failed / drift / skipped
--
-- Tenant-owned like 0001_tenancy.sql: every table has tenant_id, every unique
-- constraint starts with it, and the guard triggers at the end refuse a
-- reference to another tenant's row. Deviations from the design DDL: no
-- connection requirement (connection_id is optional; the target carries its own
-- endpoint and sealed credential), sealed secret column, run table, change
-- token and members cache on grp_sync_groups, needs_full and a timestamped
-- audit trail (created/updated).

CREATE TABLE IF NOT EXISTS grp_provisioners (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  target_type TEXT NOT NULL CHECK (target_type IN ('ldap','ad','scim2','sql','webhook')),
  connection_id TEXT REFERENCES connections (id),
  -- non-secret target settings (JSON object); validated by internal/groups/provisioning
  config TEXT NOT NULL CHECK (json_valid(config)),
  -- JSON of the target's credentials, sealed under the KEK; NULL when it has none. Never returned by the API.
  secret_enc BLOB,
  mode TEXT NOT NULL DEFAULT 'adopt' CHECK (mode IN ('adopt','dry_run','active','paused')),
  -- "M H * * *": the UTC time of the daily full sync
  full_schedule TEXT NOT NULL DEFAULT '0 2 * * *',
  failsafe TEXT NOT NULL CHECK (json_valid(failsafe)),
  -- set by a change to marks, config or mode: the next run is a full sync
  needs_full INTEGER NOT NULL DEFAULT 1 CHECK (needs_full IN (0,1)),
  -- an admin approved the failsafe limits for the next full sync (cleared when it finishes)
  approve_next INTEGER NOT NULL DEFAULT 0 CHECK (approve_next IN (0,1)),
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS grp_provisionable (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provisioner_id TEXT NOT NULL REFERENCES grp_provisioners (id),
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group')),
  -- a grp_folders or grp_groups id, by object_type (no foreign key: a folder can be deleted)
  object_id TEXT NOT NULL,
  -- a group's mark is 'self'; a folder's is 'one' (its own groups) or 'sub' (the whole subtree)
  scope TEXT NOT NULL DEFAULT 'self' CHECK (scope IN ('self','one','sub')),
  include INTEGER NOT NULL DEFAULT 1 CHECK (include IN (0,1)),
  -- per-group target settings (AD group scope, a name override, ...) as a JSON object
  metadata TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata)),
  PRIMARY KEY (tenant_id, provisioner_id, object_type, object_id),
  CHECK ((object_type = 'group') = (scope = 'self'))
);

CREATE TABLE IF NOT EXISTS grp_sync_groups (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provisioner_id TEXT NOT NULL REFERENCES grp_provisioners (id),
  group_id TEXT NOT NULL REFERENCES grp_groups (id),
  target_id TEXT,
  target_name TEXT,
  -- hash of the last-read target state (attributes and members)
  state_hash TEXT,
  -- the target's change token for that state (LDAP modifyTimestamp, a SCIM meta.version)
  change_token TEXT,
  -- the last-read attributes and members (JSON object), so a full sync can skip re-reading an unchanged group
  state_cache TEXT CHECK (state_cache IS NULL OR json_valid(state_cache)),
  last_read_at TEXT,
  last_verified_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('adopted','synced','drift','failed','removed')),
  PRIMARY KEY (tenant_id, provisioner_id, group_id)
);
CREATE INDEX IF NOT EXISTS grp_sync_groups_name ON grp_sync_groups (tenant_id, provisioner_id, target_name);

CREATE TABLE IF NOT EXISTS grp_sync_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provisioner_id TEXT NOT NULL REFERENCES grp_provisioners (id),
  kind TEXT NOT NULL CHECK (kind IN ('full','incremental')),
  -- the provisioner's mode when the run started
  mode TEXT NOT NULL CHECK (mode IN ('adopt','dry_run','active')),
  status TEXT NOT NULL CHECK (status IN ('running','done','held','failed')),
  -- the events the run covers: (from_seq, to_seq]
  from_seq INTEGER NOT NULL DEFAULT 0,
  to_seq INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(summary)),
  error TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT
);
CREATE INDEX IF NOT EXISTS grp_sync_runs_prov ON grp_sync_runs (tenant_id, provisioner_id, started_at);

CREATE TABLE IF NOT EXISTS grp_sync_ops (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  provisioner_id TEXT NOT NULL REFERENCES grp_provisioners (id),
  run_id TEXT REFERENCES grp_sync_runs (id),
  -- create | update | members | delete
  op TEXT NOT NULL CHECK (op IN ('create','update','members','delete')),
  -- the target group name
  object_ref TEXT NOT NULL,
  group_id TEXT REFERENCES grp_groups (id),
  payload_hash TEXT NOT NULL,
  -- {"add":n,"remove":n} and the reason an op was not applied
  detail TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
  -- grp_events.seq of the newest event behind an incremental op
  cause_seq INTEGER,
  status TEXT NOT NULL CHECK (status IN ('planned','applied','verified','failed','drift','skipped')),
  attempts INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  planned_at TEXT NOT NULL,
  applied_at TEXT,
  verified_at TEXT
);
CREATE INDEX IF NOT EXISTS grp_sync_ops_prov ON grp_sync_ops (tenant_id, provisioner_id, planned_at);
CREATE INDEX IF NOT EXISTS grp_sync_ops_run ON grp_sync_ops (tenant_id, run_id);

-- ---------------------------------------------------------------- guards

CREATE TRIGGER IF NOT EXISTS tg_grp_provisioners_xtenant_ins BEFORE INSERT ON grp_provisioners
WHEN NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_provisioners'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_provisioners_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON grp_provisioners
WHEN NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_provisioners'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_provisionable_xtenant_ins BEFORE INSERT ON grp_provisionable
WHEN EXISTS (SELECT 1 FROM grp_provisioners p WHERE p.id = NEW.provisioner_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_provisionable'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_provisionable_xtenant_upd BEFORE UPDATE OF tenant_id, provisioner_id, object_type, object_id ON grp_provisionable
WHEN EXISTS (SELECT 1 FROM grp_provisioners p WHERE p.id = NEW.provisioner_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.object_type = 'folder' AND EXISTS (SELECT 1 FROM grp_folders p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.object_type = 'group' AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.object_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_provisionable'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_sync_groups_xtenant_ins BEFORE INSERT ON grp_sync_groups
WHEN EXISTS (SELECT 1 FROM grp_provisioners p WHERE p.id = NEW.provisioner_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_sync_groups'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_sync_groups_xtenant_upd BEFORE UPDATE OF tenant_id, provisioner_id, group_id ON grp_sync_groups
WHEN EXISTS (SELECT 1 FROM grp_provisioners p WHERE p.id = NEW.provisioner_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_sync_groups'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_sync_runs_xtenant_ins BEFORE INSERT ON grp_sync_runs
WHEN EXISTS (SELECT 1 FROM grp_provisioners p WHERE p.id = NEW.provisioner_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_sync_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_sync_runs_xtenant_upd BEFORE UPDATE OF tenant_id, provisioner_id ON grp_sync_runs
WHEN EXISTS (SELECT 1 FROM grp_provisioners p WHERE p.id = NEW.provisioner_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_sync_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_sync_ops_xtenant_ins BEFORE INSERT ON grp_sync_ops
WHEN EXISTS (SELECT 1 FROM grp_provisioners p WHERE p.id = NEW.provisioner_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_sync_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_sync_ops'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_sync_ops_xtenant_upd BEFORE UPDATE OF tenant_id, provisioner_id, run_id, group_id ON grp_sync_ops
WHEN EXISTS (SELECT 1 FROM grp_provisioners p WHERE p.id = NEW.provisioner_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_sync_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.group_id IS NOT NULL AND EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_sync_ops'); END;
