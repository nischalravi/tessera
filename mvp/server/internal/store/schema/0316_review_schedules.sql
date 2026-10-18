-- Scheduled and recurring access reviews (issue #166).
--
-- review_templates describe a recurring campaign: its scope (one system or
-- every system; privileged grants only or all risky grants), how long
-- reviewers have (duration_days), when reminders go out, what happens to
-- items nobody decided (close_out: 'revoke', or 'escalate' to
-- escalation_identity_id for escalation_days and then revoke), and the
-- recurrence (once, quarterly, semiannual, annual) with the next run.
--
-- review_launches record each run: one per template and period
-- (period_key, e.g. "2026-Q4"), so a restart or a second scheduler never
-- launches a period twice. A launch links its campaign, its due time, when
-- reminders went out, when it escalated and when it closed.
CREATE TABLE IF NOT EXISTS review_templates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  system TEXT,
  privileged_only INTEGER NOT NULL DEFAULT 0,
  unused_days INTEGER NOT NULL DEFAULT 60 CHECK (unused_days BETWEEN 1 AND 365),
  duration_days INTEGER NOT NULL DEFAULT 14 CHECK (duration_days BETWEEN 1 AND 90),
  reminder_days INTEGER NOT NULL DEFAULT 3 CHECK (reminder_days >= 0),
  close_out TEXT NOT NULL DEFAULT 'revoke' CHECK (close_out IN ('revoke','escalate')),
  escalation_identity_id INTEGER REFERENCES identities (id),
  escalation_days INTEGER NOT NULL DEFAULT 7 CHECK (escalation_days BETWEEN 1 AND 30),
  recurrence TEXT NOT NULL CHECK (recurrence IN ('once','quarterly','semiannual','annual')),
  next_run_at TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_by TEXT REFERENCES platform_users (id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (close_out <> 'escalate' OR escalation_identity_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS ix_review_templates_tenant_next ON review_templates (tenant_id, enabled, next_run_at);

CREATE TABLE IF NOT EXISTS review_launches (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  template_id TEXT NOT NULL REFERENCES review_templates (id),
  period_key TEXT NOT NULL,
  campaign_id INTEGER NOT NULL REFERENCES review_campaigns (id),
  launched_at TEXT NOT NULL,
  due_at TEXT NOT NULL,
  reminded_at TEXT,
  escalated_at TEXT,
  closed_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, template_id, period_key)
);
CREATE INDEX IF NOT EXISTS ix_review_launches_tenant_open ON review_launches (tenant_id, closed_at, due_at);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_review_templates_xtenant_ins BEFORE INSERT ON review_templates
WHEN (NEW.escalation_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.escalation_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_templates'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_templates_xtenant_upd BEFORE UPDATE OF tenant_id, escalation_identity_id, created_by ON review_templates
WHEN (NEW.escalation_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.escalation_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_templates'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_launches_xtenant_ins BEFORE INSERT ON review_launches
WHEN EXISTS (SELECT 1 FROM review_templates p WHERE p.id = NEW.template_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_launches'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_launches_xtenant_upd BEFORE UPDATE OF tenant_id, template_id, campaign_id ON review_launches
WHEN EXISTS (SELECT 1 FROM review_templates p WHERE p.id = NEW.template_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM review_campaigns p WHERE p.id = NEW.campaign_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_launches'); END;
