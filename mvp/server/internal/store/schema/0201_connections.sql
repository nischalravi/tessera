-- Deployment readiness: connections and their revisions (design §8.3).
--
-- Tenant-owned like every table of 0001_tenancy.sql: tenant_id references
-- tenants(id), every UNIQUE constraint starts with tenant_id, and the guard
-- triggers at the end refuse a reference to another tenant's row. UUID text
-- primary keys are global (like the integer ones); another tenant's id is
-- indistinguishable from a missing one.
CREATE TABLE IF NOT EXISTS connections (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  connector_type TEXT NOT NULL,
  system TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'account_source' CHECK (role IN ('authoritative','account_source')),
  active_revision_id TEXT REFERENCES connection_revisions (id),
  health TEXT NOT NULL DEFAULT 'none' CHECK (health IN ('none','ok','degraded')),
  technical_owner_id TEXT, business_owner TEXT, agent_id TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, retired_at TEXT,
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, system)
);
CREATE INDEX IF NOT EXISTS connections_tenant ON connections(tenant_id);

-- state is written only by internal/readiness through store.SetRevisionState
-- (TestOnlyReadinessWritesConnectionState). evidence_seq increments on every
-- change of the evidence a gate reads, so activation can compare-and-set.
CREATE TABLE IF NOT EXISTS connection_revisions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  rev INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('draft','ready_to_validate','validated','dry_run_reconciled','active','degraded','retired','superseded')),
  template_id TEXT NOT NULL, template_version TEXT NOT NULL, overlay_version INTEGER NOT NULL DEFAULT 0,
  config TEXT NOT NULL,
  secret_ref TEXT, secret_version TEXT,
  config_hash TEXT NOT NULL,
  evidence_seq INTEGER NOT NULL DEFAULT 0,
  write_mode TEXT NOT NULL DEFAULT 'off' CHECK (write_mode IN ('off','dry_run','scoped')),
  expected_counts TEXT,
  gate_report TEXT,
  activated_at TEXT, activated_by TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connection_id, rev)
);
-- at most one live and one in-progress revision per connection
CREATE UNIQUE INDEX IF NOT EXISTS conn_rev_live ON connection_revisions(tenant_id, connection_id)
  WHERE state IN ('active','degraded');
CREATE UNIQUE INDEX IF NOT EXISTS conn_rev_pending ON connection_revisions(tenant_id, connection_id)
  WHERE state IN ('draft','ready_to_validate','validated','dry_run_reconciled');

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_connections_xtenant_ins BEFORE INSERT ON connections
WHEN (NEW.active_revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.active_revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connections'); END;

CREATE TRIGGER IF NOT EXISTS tg_connections_xtenant_upd BEFORE UPDATE OF tenant_id, active_revision_id ON connections
WHEN (NEW.active_revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.active_revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connections'); END;

CREATE TRIGGER IF NOT EXISTS tg_connection_revisions_xtenant_ins BEFORE INSERT ON connection_revisions
WHEN (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connection_revisions'); END;

CREATE TRIGGER IF NOT EXISTS tg_connection_revisions_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON connection_revisions
WHEN (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connection_revisions'); END;

