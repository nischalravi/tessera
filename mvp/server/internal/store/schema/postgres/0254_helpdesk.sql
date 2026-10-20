-- Postgres dialect of schema/0254_helpdesk.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE helpdesk_cases (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('password','mfa')),
  system TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','executing','executed','failed','cancelled')),
  privileged BIGINT NOT NULL DEFAULT 0,
  requested_by TEXT NOT NULL,
  requested_by_user_id TEXT,
  second_approver TEXT,
  second_approver_user_id TEXT,
  second_approved_at TEXT,
  executed_by TEXT,
  executed_at TEXT,
  result TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by_user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, second_approver_user_id) REFERENCES platform_users (tenant_id, id),
  UNIQUE (tenant_id, id)
);
CREATE INDEX ix_helpdesk_cases_tenant_created ON helpdesk_cases (tenant_id, created_at);
CREATE INDEX ix_helpdesk_cases_identity ON helpdesk_cases (tenant_id, identity_id, status);

CREATE TABLE helpdesk_verifications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  case_id TEXT NOT NULL,
  method TEXT NOT NULL CHECK (method IN ('push','callback','manager_approval','idv')),
  outcome TEXT NOT NULL CHECK (outcome IN ('passed','failed')),
  phishing_resistant BIGINT NOT NULL DEFAULT 0,
  verified_by TEXT NOT NULL,
  verified_by_user_id TEXT,
  evidence TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, case_id) REFERENCES helpdesk_cases (tenant_id, id),
  FOREIGN KEY (tenant_id, verified_by_user_id) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_helpdesk_verifications_case ON helpdesk_verifications (tenant_id, case_id, created_at);

CREATE TABLE helpdesk_signals (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('mfa_device_added','sign_in')),
  location TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  occurred_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX ix_helpdesk_signals_identity ON helpdesk_signals (tenant_id, identity_id, occurred_at);

CREATE TABLE helpdesk_findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  case_id TEXT NOT NULL,
  identity_id BIGINT NOT NULL,
  rule TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, case_id) REFERENCES helpdesk_cases (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
CREATE UNIQUE INDEX ux_helpdesk_findings_case_rule ON helpdesk_findings (tenant_id, case_id, rule);
CREATE INDEX ix_helpdesk_findings_created ON helpdesk_findings (tenant_id, created_at);
