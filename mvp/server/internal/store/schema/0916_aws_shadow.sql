-- Production shadow agreement for AWS decisions (issue #641, EP-6; design
-- docs/design/differentiators-plan.md section 1).
--
-- A tenant that opts in (aws_shadow_settings) has up to daily_k of the
-- evaluator's decisions a day compared with iam:SimulatePrincipalPolicy in the
-- customer account. Each comparison is one aws_shadow_checks row. A
-- 'disagree' row is the finding: it starts 'open' and is triaged by a person;
-- every triage step is a row of aws_shadow_triage, and the check keeps the
-- current state. connector_id and snapshot_id are not foreign keys: the
-- history outlives a deleted connector and a retired snapshot.
--
-- Tenant-owned like 0001_tenancy.sql: tenant_id on every row, every unique
-- index starts with it, every statement binds it.
CREATE TABLE IF NOT EXISTS aws_shadow_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  daily_k INTEGER NOT NULL DEFAULT 20 CHECK (daily_k BETWEEN 1 AND 200),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id)
);

CREATE TABLE IF NOT EXISTS aws_shadow_checks (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  sample_day TEXT NOT NULL,                -- the UTC date the sample counts against (YYYY-MM-DD)
  principal_arn TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_arn TEXT NOT NULL,
  tessera_outcome TEXT NOT NULL CHECK (tessera_outcome IN ('allow', 'deny')),
  tessera_fidelity TEXT NOT NULL,
  explanation_id TEXT NOT NULL DEFAULT '',
  aws_decision TEXT NOT NULL DEFAULT '',   -- allowed, explicitDeny, implicitDeny; empty when the call failed
  verdict TEXT NOT NULL CHECK (verdict IN ('agree', 'disagree', 'inconclusive', 'error')),
  detail TEXT NOT NULL DEFAULT '',
  checked_at TEXT NOT NULL,
  triage_status TEXT NOT NULL DEFAULT 'none'
    CHECK (triage_status IN ('none', 'open', 'investigating', 'engine_bug', 'expected', 'resolved')),
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS aws_shadow_checks_day ON aws_shadow_checks (tenant_id, sample_day);
CREATE INDEX IF NOT EXISTS aws_shadow_checks_verdict ON aws_shadow_checks (tenant_id, verdict, triage_status, checked_at);

CREATE TABLE IF NOT EXISTS aws_shadow_triage (
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
CREATE INDEX IF NOT EXISTS aws_shadow_triage_check ON aws_shadow_triage (tenant_id, check_id, created_at);
