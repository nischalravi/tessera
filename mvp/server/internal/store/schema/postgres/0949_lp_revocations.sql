-- Postgres dialect of schema/0921_lp_revocations.sql (issue #661, kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). connector_id, snapshot_id, op_id and restore_op_id are deliberately not
-- foreign keys (the history outlives them); see 0001_tenancy.sql for the tenant rules.

-- +goose Up

CREATE TABLE lp_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  mode TEXT NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'suggest', 'staged', 'auto')),
  paused BIGINT NOT NULL DEFAULT 0 CHECK (paused IN (0, 1)),
  paused_reason TEXT NOT NULL DEFAULT '',
  paused_by TEXT NOT NULL DEFAULT '',
  paused_at TEXT,
  cap_per_run BIGINT NOT NULL DEFAULT 25 CHECK (cap_per_run BETWEEN 1 AND 1000),
  cap_per_day BIGINT NOT NULL DEFAULT 100 CHECK (cap_per_day BETWEEN 1 AND 10000),
  cap_per_account BIGINT NOT NULL DEFAULT 10 CHECK (cap_per_account BETWEEN 1 AND 1000),
  cap_per_principal BIGINT NOT NULL DEFAULT 1 CHECK (cap_per_principal BETWEEN 1 AND 100),
  announce_days BIGINT NOT NULL DEFAULT 7 CHECK (announce_days BETWEEN 1 AND 90),
  finalize_days BIGINT NOT NULL DEFAULT 30 CHECK (finalize_days BETWEEN 1 AND 365),
  auto_min_days BIGINT NOT NULL DEFAULT 90 CHECK (auto_min_days BETWEEN 1 AND 365),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id)
);

CREATE TABLE lp_revocations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('candidate', 'announced', 'revoking', 'revoked', 'finalized', 'restoring',
    'restored', 'exempted', 'failed', 'superseded')),
  kind TEXT NOT NULL CHECK (kind IN ('aws_detach_policy', 'aws_delete_inline_policy', 'aws_set_policy_version',
    'aws_remove_from_group', 'aws_delete_assignment')),
  eligibility TEXT NOT NULL CHECK (eligibility IN ('auto', 'item')),
  connector_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  principal_arn TEXT NOT NULL,
  policy_arn TEXT NOT NULL,
  unused_days BIGINT NOT NULL CHECK (unused_days >= 1),
  confidence TEXT NOT NULL CHECK (confidence IN ('high', 'medium')),
  evidence TEXT NOT NULL,
  candidate_sha256 TEXT NOT NULL CHECK (length(candidate_sha256) = 64),
  restore_payload TEXT NOT NULL,
  restore_sha256 TEXT NOT NULL CHECK (length(restore_sha256) = 64),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  approved_by TEXT NOT NULL DEFAULT '',
  approved_at TEXT,
  announce_until TEXT,
  executed_at TEXT,
  op_id TEXT NOT NULL DEFAULT '',
  revoked_at TEXT,
  restore_until TEXT,
  finalized_at TEXT,
  restore_op_id TEXT NOT NULL DEFAULT '',
  restore_trigger TEXT NOT NULL DEFAULT '',
  restore_requested_at TEXT,
  restored_at TEXT,
  reason TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX lp_revocations_state ON lp_revocations (tenant_id, state, created_at);
CREATE INDEX lp_revocations_principal ON lp_revocations (tenant_id, principal_arn, policy_arn);
CREATE INDEX lp_revocations_executed ON lp_revocations (tenant_id, executed_at);

CREATE TABLE lp_revocation_events (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  revocation_id TEXT NOT NULL,
  from_state TEXT NOT NULL,
  to_state TEXT NOT NULL,
  actor TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, revocation_id) REFERENCES lp_revocations (tenant_id, id)
);
CREATE INDEX lp_revocation_events_rev ON lp_revocation_events (tenant_id, revocation_id, created_at);

CREATE TABLE lp_protected (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('principal', 'policy')),
  ref TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX lp_protected_ref ON lp_protected (tenant_id, kind, ref);

CREATE TABLE lp_exemptions (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  principal_arn TEXT NOT NULL,
  policy_arn TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('objection', 'restore', 'review_keep')),
  reason TEXT NOT NULL DEFAULT '',
  revocation_id TEXT NOT NULL DEFAULT '',
  ends_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX lp_exemptions_grant ON lp_exemptions (tenant_id, principal_arn, policy_arn, ends_at);
