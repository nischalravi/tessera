-- Postgres dialect of schema/0201_connections.sql (Phase 0 PR14). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE connections (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  connector_type TEXT NOT NULL,
  system TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'account_source' CHECK (role IN ('authoritative','account_source')),
  active_revision_id TEXT,
  health TEXT NOT NULL DEFAULT 'none' CHECK (health IN ('none','ok','degraded')),
  technical_owner_id TEXT, business_owner TEXT, agent_id TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, retired_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, system)
);
CREATE INDEX connections_tenant ON connections(tenant_id);

CREATE TABLE connection_revisions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL,
  rev BIGINT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('draft','ready_to_validate','validated','dry_run_reconciled','active','degraded','retired','superseded')),
  template_id TEXT NOT NULL, template_version TEXT NOT NULL, overlay_version BIGINT NOT NULL DEFAULT 0,
  config TEXT NOT NULL,
  secret_ref TEXT, secret_version TEXT,
  config_hash TEXT NOT NULL,
  evidence_seq BIGINT NOT NULL DEFAULT 0,
  write_mode TEXT NOT NULL DEFAULT 'off' CHECK (write_mode IN ('off','dry_run','scoped')),
  expected_counts TEXT,
  gate_report TEXT,
  activated_at TEXT, activated_by TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, connection_id, rev),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
-- at most one live and one in-progress revision per connection
CREATE UNIQUE INDEX conn_rev_live ON connection_revisions(tenant_id, connection_id)
  WHERE state IN ('active','degraded');
CREATE UNIQUE INDEX conn_rev_pending ON connection_revisions(tenant_id, connection_id)
  WHERE state IN ('draft','ready_to_validate','validated','dry_run_reconciled');

-- connections and their revisions reference each other
ALTER TABLE connections ADD FOREIGN KEY (tenant_id, active_revision_id) REFERENCES connection_revisions (tenant_id, id);
