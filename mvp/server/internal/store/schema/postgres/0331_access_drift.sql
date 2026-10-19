-- Postgres dialect of schema/0331_access_drift.sql (issue #301, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE access_drift (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  drift_key TEXT NOT NULL,
  class TEXT NOT NULL CHECK (class IN ('missing','rogue','orphan','stale')),
  system TEXT NOT NULL,
  entitlement_kind TEXT NOT NULL DEFAULT 'group',
  entitlement_ref TEXT NOT NULL DEFAULT '',
  account_ref TEXT NOT NULL DEFAULT '',
  account_id BIGINT,
  identity_id BIGINT,
  intended_id TEXT,
  observed_id BIGINT,
  owner_identity_id BIGINT,
  status TEXT NOT NULL CHECK (status IN ('open','remediating','resolved','accepted')),
  detected_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  resolved_at TEXT,
  accepted_by TEXT,
  accepted_reason TEXT,
  action TEXT NOT NULL DEFAULT 'none' CHECK (action IN ('none','auto_provision','auto_revoke','owner_task','report_only')),
  remediation_ref TEXT,
  remediation_note TEXT,
  remediation_at TEXT,
  UNIQUE (tenant_id, drift_key),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, intended_id) REFERENCES intended_grants (tenant_id, id)
);
CREATE INDEX ix_access_drift_status ON access_drift (tenant_id, status, class);
CREATE INDEX ix_access_drift_system ON access_drift (tenant_id, system);

CREATE TABLE remediation_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  entitlement_ref TEXT NOT NULL DEFAULT '',
  drift_class TEXT NOT NULL CHECK (drift_class IN ('missing','rogue','orphan','stale')),
  action TEXT NOT NULL CHECK (action IN ('auto_provision','auto_revoke','owner_task','report_only')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, system, entitlement_ref, drift_class),
  UNIQUE (tenant_id, id)
);
