-- Dry-run staging snapshot (design §6.1, K9). Same shape as the live tables
-- plus run_id; no code path copies staged rows into live tables
-- (TestStage_NoLiveWrites). attributes holds mapped attributes only.
CREATE TABLE IF NOT EXISTS stg_identities (
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  run_id TEXT NOT NULL, external_id TEXT NOT NULL,
  name TEXT NOT NULL, email TEXT, type TEXT, status TEXT, department TEXT,
  hired_at TEXT, terminated_at TEXT, attributes TEXT,
  PRIMARY KEY (tenant_id, run_id, external_id)
);
CREATE TABLE IF NOT EXISTS stg_accounts (
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  run_id TEXT NOT NULL, system TEXT NOT NULL, external_id TEXT NOT NULL,
  username TEXT, kind TEXT, status TEXT, created_at TEXT, last_login_at TEXT,
  attributes TEXT,
  correlation TEXT,
  tier INTEGER,
  identity_id INTEGER, proposed_identity_id INTEGER,
  PRIMARY KEY (tenant_id, run_id, system, external_id)
);
CREATE TABLE IF NOT EXISTS stg_groups (
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  run_id TEXT NOT NULL, system TEXT NOT NULL, external_id TEXT NOT NULL,
  name TEXT NOT NULL, kind TEXT, privileged INTEGER NOT NULL DEFAULT 0, in_scope INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, run_id, system, external_id)
);
CREATE TABLE IF NOT EXISTS stg_memberships (
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  run_id TEXT NOT NULL,
  member_kind TEXT NOT NULL, member_xid TEXT NOT NULL, group_xid TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id, member_kind, member_xid, group_xid)
);
CREATE TABLE IF NOT EXISTS stg_attr_stats (
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  run_id TEXT NOT NULL, object_class TEXT NOT NULL, attribute TEXT NOT NULL,
  total INTEGER NOT NULL, present INTEGER NOT NULL, distinct_values INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, run_id, object_class, attribute)
);
