-- Postgres dialect of schema/0495_org_settings.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); json_valid is IS JSON.

-- +goose Up

CREATE TABLE org_owners (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  org_id TEXT NOT NULL,
  identity_id BIGINT NOT NULL,
  ord BIGINT NOT NULL CHECK (ord >= 0),
  PRIMARY KEY (tenant_id, org_id, identity_id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);

CREATE TABLE org_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  org_id TEXT NOT NULL,
  default_stages TEXT CHECK (default_stages IS NULL OR default_stages IS JSON),
  default_escalate_hours DOUBLE PRECISION CHECK (default_escalate_hours IS NULL OR default_escalate_hours > 0),
  ov_justification_required BIGINT CHECK (ov_justification_required IS NULL OR ov_justification_required IN (0, 1)),
  ov_justification_min_length BIGINT CHECK (ov_justification_min_length IS NULL OR ov_justification_min_length BETWEEN 1 AND 1000),
  ov_default_hours DOUBLE PRECISION CHECK (ov_default_hours IS NULL OR ov_default_hours > 0),
  ov_max_hours DOUBLE PRECISION CHECK (ov_max_hours IS NULL OR ov_max_hours > 0),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, org_id)
);

CREATE TABLE org_hierarchy_source (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  source TEXT NOT NULL DEFAULT 'hr_department' CHECK (source IN ('hr_department')),
  system TEXT,
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
