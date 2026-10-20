-- Verified help-desk reset workflow (issue #108): password and MFA resets that
-- cannot run until a verification policy is satisfied, and the post-reset
-- signals the account-takeover detection reads.
--
-- helpdesk_cases: one reset case for one identity. status moves open ->
-- executing -> executed (or failed, which can be retried; or cancelled). The
-- reset itself is run through the IdP by internal/helpdesk; no secret (a
-- temporary access pass, a password) is ever stored here. second_approver_* is
-- the second approver a privileged identity needs.
-- helpdesk_verifications: append-only attestations, one row per attempt.
-- helpdesk_signals: post-reset telemetry (a new MFA device, a sign-in and its
-- location), fed by the IdP log connectors or the simulator.
-- helpdesk_findings: the detection's output, one per case and rule.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's identity, platform user or case.
CREATE TABLE IF NOT EXISTS helpdesk_cases (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  kind TEXT NOT NULL CHECK (kind IN ('password','mfa')),
  system TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','executing','executed','failed','cancelled')),
  privileged INTEGER NOT NULL DEFAULT 0,
  requested_by TEXT NOT NULL,
  requested_by_user_id TEXT REFERENCES platform_users (id),
  second_approver TEXT,
  second_approver_user_id TEXT REFERENCES platform_users (id),
  second_approved_at TEXT,
  executed_by TEXT,
  executed_at TEXT,
  result TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_helpdesk_cases_tenant_created ON helpdesk_cases (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS ix_helpdesk_cases_identity ON helpdesk_cases (tenant_id, identity_id, status);

CREATE TABLE IF NOT EXISTS helpdesk_verifications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  case_id TEXT NOT NULL REFERENCES helpdesk_cases (id),
  method TEXT NOT NULL CHECK (method IN ('push','callback','manager_approval','idv')),
  outcome TEXT NOT NULL CHECK (outcome IN ('passed','failed')),
  phishing_resistant INTEGER NOT NULL DEFAULT 0,
  verified_by TEXT NOT NULL,
  verified_by_user_id TEXT REFERENCES platform_users (id),
  evidence TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_helpdesk_verifications_case ON helpdesk_verifications (tenant_id, case_id, created_at);

CREATE TABLE IF NOT EXISTS helpdesk_signals (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  kind TEXT NOT NULL CHECK (kind IN ('mfa_device_added','sign_in')),
  location TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  occurred_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_helpdesk_signals_identity ON helpdesk_signals (tenant_id, identity_id, occurred_at);

CREATE TABLE IF NOT EXISTS helpdesk_findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  case_id TEXT NOT NULL REFERENCES helpdesk_cases (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  rule TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_helpdesk_findings_case_rule ON helpdesk_findings (tenant_id, case_id, rule);
CREATE INDEX IF NOT EXISTS ix_helpdesk_findings_created ON helpdesk_findings (tenant_id, created_at);

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_cases_xtenant_ins BEFORE INSERT ON helpdesk_cases
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.requested_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.second_approver_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.second_approver_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_cases'); END;

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_cases_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, requested_by_user_id, second_approver_user_id ON helpdesk_cases
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.requested_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.second_approver_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.second_approver_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_cases'); END;

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_verifications_xtenant_ins BEFORE INSERT ON helpdesk_verifications
WHEN EXISTS (SELECT 1 FROM helpdesk_cases p WHERE p.id = NEW.case_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.verified_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.verified_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_verifications'); END;

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_verifications_xtenant_upd BEFORE UPDATE OF tenant_id, case_id, verified_by_user_id ON helpdesk_verifications
WHEN EXISTS (SELECT 1 FROM helpdesk_cases p WHERE p.id = NEW.case_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.verified_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.verified_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_verifications'); END;

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_signals_xtenant_ins BEFORE INSERT ON helpdesk_signals
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_signals'); END;

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_signals_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON helpdesk_signals
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_signals'); END;

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_findings_xtenant_ins BEFORE INSERT ON helpdesk_findings
WHEN EXISTS (SELECT 1 FROM helpdesk_cases p WHERE p.id = NEW.case_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_findings'); END;

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_findings_xtenant_upd BEFORE UPDATE OF tenant_id, case_id, identity_id ON helpdesk_findings
WHEN EXISTS (SELECT 1 FROM helpdesk_cases p WHERE p.id = NEW.case_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_findings'); END;
