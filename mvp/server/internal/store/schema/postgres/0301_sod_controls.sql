-- Postgres dialect of schema/0301_sod_controls.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE sod_controls (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  owner_identity_id BIGINT,
  type TEXT NOT NULL CHECK (type IN ('preventive','detective','corrective')),
  frequency TEXT NOT NULL CHECK (frequency IN ('continuous','daily','weekly','monthly','quarterly','annually')),
  evidence_requirement TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  version BIGINT NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  FOREIGN KEY (tenant_id, owner_identity_id) REFERENCES identities (tenant_id, id)
);

CREATE TABLE sod_mitigations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  risk_id TEXT NOT NULL,
  identity_id BIGINT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('control','accept')),
  control_id TEXT,
  justification TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL CHECK (status IN ('pending','active','rejected','cancelled','expired','revoked')),
  starts_at TEXT,
  ends_at TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  decided_by TEXT,
  decided_at TEXT,
  decision_note TEXT,
  revoked_by TEXT,
  revoke_reason TEXT,
  warned_at TEXT,
  closed_at TEXT,
  UNIQUE (tenant_id, id),
  CHECK ((kind = 'control') = (control_id IS NOT NULL)),
  FOREIGN KEY (tenant_id, risk_id) REFERENCES sod_risks (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, control_id) REFERENCES sod_controls (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, revoked_by) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_sod_mitigations_tenant_risk ON sod_mitigations (tenant_id, risk_id, identity_id);
CREATE UNIQUE INDEX ux_sod_mitigations_live ON sod_mitigations (tenant_id, risk_id, identity_id)
  WHERE status IN ('pending','active');

CREATE TABLE sod_risk_options (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  risk_id TEXT NOT NULL,
  remediation TEXT NOT NULL CHECK (remediation IN ('revoke','mitigate','accept','escalate')),
  PRIMARY KEY (tenant_id, risk_id, remediation),
  FOREIGN KEY (tenant_id, risk_id) REFERENCES sod_risks (tenant_id, id)
);

CREATE TABLE sod_escalations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  risk_id TEXT NOT NULL,
  identity_id BIGINT NOT NULL,
  escalated_by TEXT NOT NULL,
  note TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, risk_id) REFERENCES sod_risks (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, escalated_by) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_sod_escalations_tenant_risk ON sod_escalations (tenant_id, risk_id, identity_id);

CREATE TRIGGER tg_sod_controls_updated_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, updated_by ON sod_controls
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'updated_by', 'text');
