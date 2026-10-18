-- Postgres dialect of schema/0281_review_schedules.sql (issue #166, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE review_templates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  system TEXT,
  privileged_only BIGINT NOT NULL DEFAULT 0,
  unused_days BIGINT NOT NULL DEFAULT 60 CHECK (unused_days BETWEEN 1 AND 365),
  duration_days BIGINT NOT NULL DEFAULT 14 CHECK (duration_days BETWEEN 1 AND 90),
  reminder_days BIGINT NOT NULL DEFAULT 3 CHECK (reminder_days >= 0),
  close_out TEXT NOT NULL DEFAULT 'revoke' CHECK (close_out IN ('revoke','escalate')),
  escalation_identity_id BIGINT,
  escalation_days BIGINT NOT NULL DEFAULT 7 CHECK (escalation_days BETWEEN 1 AND 30),
  recurrence TEXT NOT NULL CHECK (recurrence IN ('once','quarterly','semiannual','annual')),
  next_run_at TEXT,
  enabled BIGINT NOT NULL DEFAULT 1,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  CHECK (close_out <> 'escalate' OR escalation_identity_id IS NOT NULL),
  FOREIGN KEY (tenant_id, escalation_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, created_by) REFERENCES platform_users (tenant_id, id)
);

CREATE INDEX ix_review_templates_tenant_next ON review_templates (tenant_id, enabled, next_run_at);

CREATE TABLE review_launches (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  template_id TEXT NOT NULL,
  period_key TEXT NOT NULL,
  campaign_id BIGINT NOT NULL,
  launched_at TEXT NOT NULL,
  due_at TEXT NOT NULL,
  reminded_at TEXT,
  escalated_at TEXT,
  closed_at TEXT,
  revoked BIGINT NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, template_id, period_key),
  FOREIGN KEY (tenant_id, template_id) REFERENCES review_templates (tenant_id, id),
  FOREIGN KEY (tenant_id, campaign_id) REFERENCES review_campaigns (tenant_id, id)
);

CREATE INDEX ix_review_launches_tenant_open ON review_launches (tenant_id, closed_at, due_at);
