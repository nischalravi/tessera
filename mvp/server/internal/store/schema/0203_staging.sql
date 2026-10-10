-- Dry-run staging snapshot (design §6.1, K9). Same shape as the live tables
-- plus run_id (the dry_run check run); no code path copies staged rows into
-- live tables (TestStage_NoLiveWrites). attributes holds mapped attributes
-- only. Tenant-owned: see 0201_connections.sql. stg_accounts.identity_id and
-- proposed_identity_id point at live identities, so they are guarded too.
CREATE TABLE IF NOT EXISTS stg_identities (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL REFERENCES readiness_check_runs (id), external_id TEXT NOT NULL,
  name TEXT NOT NULL, email TEXT, type TEXT, status TEXT, department TEXT,
  hired_at TEXT, terminated_at TEXT, attributes TEXT,
  PRIMARY KEY (tenant_id, run_id, external_id)
);
CREATE TABLE IF NOT EXISTS stg_accounts (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL REFERENCES readiness_check_runs (id), system TEXT NOT NULL, external_id TEXT NOT NULL,
  username TEXT, kind TEXT, status TEXT, created_at TEXT, last_login_at TEXT,
  attributes TEXT,
  correlation TEXT,
  tier INTEGER,
  identity_id INTEGER REFERENCES identities (id), proposed_identity_id INTEGER REFERENCES identities (id),
  PRIMARY KEY (tenant_id, run_id, system, external_id)
);
CREATE TABLE IF NOT EXISTS stg_groups (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL REFERENCES readiness_check_runs (id), system TEXT NOT NULL, external_id TEXT NOT NULL,
  name TEXT NOT NULL, kind TEXT, privileged INTEGER NOT NULL DEFAULT 0, in_scope INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, run_id, system, external_id)
);
CREATE TABLE IF NOT EXISTS stg_memberships (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL REFERENCES readiness_check_runs (id),
  member_kind TEXT NOT NULL, member_xid TEXT NOT NULL, group_xid TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id, member_kind, member_xid, group_xid)
);
CREATE TABLE IF NOT EXISTS stg_attr_stats (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL REFERENCES readiness_check_runs (id), object_class TEXT NOT NULL, attribute TEXT NOT NULL,
  total INTEGER NOT NULL, present INTEGER NOT NULL, distinct_values INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, run_id, object_class, attribute)
);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_stg_identities_xtenant_ins BEFORE INSERT ON stg_identities
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_identities'); END;

CREATE TRIGGER IF NOT EXISTS tg_stg_identities_xtenant_upd BEFORE UPDATE OF tenant_id, run_id ON stg_identities
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_identities'); END;

CREATE TRIGGER IF NOT EXISTS tg_stg_accounts_xtenant_ins BEFORE INSERT ON stg_accounts
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.proposed_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.proposed_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_accounts'); END;

CREATE TRIGGER IF NOT EXISTS tg_stg_accounts_xtenant_upd BEFORE UPDATE OF tenant_id, run_id, identity_id, proposed_identity_id ON stg_accounts
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.proposed_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.proposed_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_accounts'); END;

CREATE TRIGGER IF NOT EXISTS tg_stg_groups_xtenant_ins BEFORE INSERT ON stg_groups
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_groups'); END;

CREATE TRIGGER IF NOT EXISTS tg_stg_groups_xtenant_upd BEFORE UPDATE OF tenant_id, run_id ON stg_groups
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_groups'); END;

CREATE TRIGGER IF NOT EXISTS tg_stg_memberships_xtenant_ins BEFORE INSERT ON stg_memberships
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_memberships'); END;

CREATE TRIGGER IF NOT EXISTS tg_stg_memberships_xtenant_upd BEFORE UPDATE OF tenant_id, run_id ON stg_memberships
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_memberships'); END;

CREATE TRIGGER IF NOT EXISTS tg_stg_attr_stats_xtenant_ins BEFORE INSERT ON stg_attr_stats
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_attr_stats'); END;

CREATE TRIGGER IF NOT EXISTS tg_stg_attr_stats_xtenant_upd BEFORE UPDATE OF tenant_id, run_id ON stg_attr_stats
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: stg_attr_stats'); END;

