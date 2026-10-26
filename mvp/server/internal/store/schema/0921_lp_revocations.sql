-- Staged revocation of unused AWS access (issue #661, LP-5; design docs/design/least-privilege-loop.md
-- sections 3, 5 and 11). A tenant's loop settings (mode, kill switch, caps), the revocations the loop
-- proposes and carries out (a state machine: candidate, announced, revoking, revoked, finalized, with
-- restoring, restored, exempted, failed and superseded), the events of every transition, the principals and
-- policies the loop must never touch, and the exemptions that keep a grant from being proposed again.
--
-- Tenant-owned like 0001_tenancy.sql: tenant_id on every row, every unique index starts with it, every
-- statement binds it. connector_id, snapshot_id, op_id and restore_op_id are not foreign keys: the history of a
-- revocation outlives a deleted connector, a retired snapshot and a pruned provisioning operation.
CREATE TABLE IF NOT EXISTS lp_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  mode TEXT NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'suggest', 'staged', 'auto')),
  paused INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1)),
  paused_reason TEXT NOT NULL DEFAULT '',
  paused_by TEXT NOT NULL DEFAULT '',
  paused_at TEXT,
  cap_per_run INTEGER NOT NULL DEFAULT 25 CHECK (cap_per_run BETWEEN 1 AND 1000),
  cap_per_day INTEGER NOT NULL DEFAULT 100 CHECK (cap_per_day BETWEEN 1 AND 10000),
  cap_per_account INTEGER NOT NULL DEFAULT 10 CHECK (cap_per_account BETWEEN 1 AND 1000),
  cap_per_principal INTEGER NOT NULL DEFAULT 1 CHECK (cap_per_principal BETWEEN 1 AND 100),
  announce_days INTEGER NOT NULL DEFAULT 7 CHECK (announce_days BETWEEN 1 AND 90),
  finalize_days INTEGER NOT NULL DEFAULT 30 CHECK (finalize_days BETWEEN 1 AND 365),
  auto_min_days INTEGER NOT NULL DEFAULT 90 CHECK (auto_min_days BETWEEN 1 AND 365),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id)
);

CREATE TABLE IF NOT EXISTS lp_revocations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('candidate', 'announced', 'revoking', 'revoked', 'finalized', 'restoring',
    'restored', 'exempted', 'failed', 'superseded')),
  kind TEXT NOT NULL CHECK (kind IN ('aws_detach_policy', 'aws_delete_inline_policy', 'aws_set_policy_version',
    'aws_remove_from_group', 'aws_delete_assignment')),
  -- auto: high confidence and unused long enough (a batch approval covers it); item: needs its own approval
  eligibility TEXT NOT NULL CHECK (eligibility IN ('auto', 'item')),
  connector_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  account_id TEXT NOT NULL,                 -- the AWS account of the principal (the per-account cap)
  principal_arn TEXT NOT NULL,
  policy_arn TEXT NOT NULL,
  unused_days INTEGER NOT NULL CHECK (unused_days >= 1),
  confidence TEXT NOT NULL CHECK (confidence IN ('high', 'medium')),
  evidence TEXT NOT NULL,                   -- JSON: confidence reasons, verification verdict and diff summary
  candidate_sha256 TEXT NOT NULL CHECK (length(candidate_sha256) = 64),
  -- the exact prior state, verbatim (JSON), and its digest recorded at the revoke (restore refuses a different one)
  restore_payload TEXT NOT NULL,
  restore_sha256 TEXT NOT NULL CHECK (length(restore_sha256) = 64),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  approved_by TEXT NOT NULL DEFAULT '',
  approved_at TEXT,
  announce_until TEXT,
  executed_at TEXT,                         -- when the operation was queued: what the caps count
  op_id TEXT NOT NULL DEFAULT '',
  revoked_at TEXT,
  restore_until TEXT,                       -- the finalize time
  finalized_at TEXT,
  restore_op_id TEXT NOT NULL DEFAULT '',
  restore_trigger TEXT NOT NULL DEFAULT '', -- denial, jit, owner, admin, undo_run
  restore_requested_at TEXT,
  restored_at TEXT,
  reason TEXT NOT NULL DEFAULT '',          -- why it was exempted, failed or superseded
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS lp_revocations_state ON lp_revocations (tenant_id, state, created_at);
CREATE INDEX IF NOT EXISTS lp_revocations_principal ON lp_revocations (tenant_id, principal_arn, policy_arn);
CREATE INDEX IF NOT EXISTS lp_revocations_executed ON lp_revocations (tenant_id, executed_at);

CREATE TABLE IF NOT EXISTS lp_revocation_events (
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
CREATE INDEX IF NOT EXISTS lp_revocation_events_rev ON lp_revocation_events (tenant_id, revocation_id, created_at);

CREATE TABLE IF NOT EXISTS lp_protected (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('principal', 'policy')),
  ref TEXT NOT NULL,                        -- an IAM principal ARN or a policy ARN
  reason TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS lp_protected_ref ON lp_protected (tenant_id, kind, ref);

CREATE TABLE IF NOT EXISTS lp_exemptions (
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
CREATE INDEX IF NOT EXISTS lp_exemptions_grant ON lp_exemptions (tenant_id, principal_arn, policy_arn, ends_at);

CREATE TRIGGER IF NOT EXISTS tg_lp_revocation_events_xtenant_ins BEFORE INSERT ON lp_revocation_events
WHEN NOT EXISTS (SELECT 1 FROM lp_revocations p WHERE p.id = NEW.revocation_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: lp_revocation_events'); END;

CREATE TRIGGER IF NOT EXISTS tg_lp_revocation_events_xtenant_upd BEFORE UPDATE OF tenant_id, revocation_id ON lp_revocation_events
WHEN NOT EXISTS (SELECT 1 FROM lp_revocations p WHERE p.id = NEW.revocation_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: lp_revocation_events'); END;
