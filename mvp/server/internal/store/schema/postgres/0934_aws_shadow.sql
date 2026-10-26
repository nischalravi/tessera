-- Postgres dialect of schema/0916_aws_shadow.sql (issue #641, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). connector_id and snapshot_id are deliberately not foreign
-- keys (the history outlives them); see 0001_tenancy.sql for the tenant rules.

-- +goose Up

CREATE TABLE aws_shadow_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  enabled BIGINT NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  daily_k BIGINT NOT NULL DEFAULT 20 CHECK (daily_k BETWEEN 1 AND 200),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id)
);

CREATE TABLE aws_shadow_checks (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  sample_day TEXT NOT NULL,
  principal_arn TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_arn TEXT NOT NULL,
  tessera_outcome TEXT NOT NULL CHECK (tessera_outcome IN ('allow', 'deny')),
  tessera_fidelity TEXT NOT NULL,
  explanation_id TEXT NOT NULL DEFAULT '',
  aws_decision TEXT NOT NULL DEFAULT '',
  verdict TEXT NOT NULL CHECK (verdict IN ('agree', 'disagree', 'inconclusive', 'error')),
  detail TEXT NOT NULL DEFAULT '',
  checked_at TEXT NOT NULL,
  triage_status TEXT NOT NULL DEFAULT 'none'
    CHECK (triage_status IN ('none', 'open', 'investigating', 'engine_bug', 'expected', 'resolved')),
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX aws_shadow_checks_day ON aws_shadow_checks (tenant_id, sample_day);
CREATE INDEX aws_shadow_checks_verdict ON aws_shadow_checks (tenant_id, verdict, triage_status, checked_at);

CREATE TABLE aws_shadow_triage (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'engine_bug', 'expected', 'resolved')),
  note TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, check_id) REFERENCES aws_shadow_checks (tenant_id, id)
);
CREATE INDEX aws_shadow_triage_check ON aws_shadow_triage (tenant_id, check_id, created_at);
