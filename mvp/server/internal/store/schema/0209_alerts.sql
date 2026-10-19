-- Alerting: rules, alerts and delivery channels (issue #168).
--
-- The rules themselves are built in (internal/alerts); alert_rule_settings
-- holds a tenant's overrides of a rule: on or off, severity, threshold and
-- window. A rule without a row runs with its defaults.
--
-- alerts are raised by the engine from audit events and detections. One
-- alert is open per (rule, dedup_key): a repeat bumps its count and
-- last_seen_at instead of raising another. States: open, acknowledged,
-- resolved. assignee_user_id is a platform user.
--
-- alert_channels are where alerts go: email (target = addresses) or a
-- webhook (target = an https URL, Slack- and Teams-compatible). A webhook's
-- signing secret is sealed under the KEK (AAD alert_channels.secret.<id>).
-- min_severity filters what a channel receives.
--
-- alert_deliveries are the outbox: one row per alert and channel, retried
-- with backoff until sent or given up.
--
-- alert_cursors keep, per tenant, the last audit seq the engine has read.
CREATE TABLE IF NOT EXISTS alert_rule_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  rule_id TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  threshold INTEGER NOT NULL CHECK (threshold BETWEEN 1 AND 10000),
  window_minutes INTEGER NOT NULL CHECK (window_minutes BETWEEN 1 AND 10080),
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, rule_id)
);

CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  rule_id TEXT NOT NULL,
  dedup_key TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved')),
  count INTEGER NOT NULL DEFAULT 1,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_event_seq INTEGER,
  assignee_user_id TEXT REFERENCES platform_users (id),
  acknowledged_by TEXT REFERENCES platform_users (id),
  acknowledged_at TEXT,
  resolved_by TEXT REFERENCES platform_users (id),
  resolved_at TEXT,
  resolution TEXT
);
-- one live alert per rule and key; resolved ones are history
CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_tenant_live ON alerts (tenant_id, rule_id, dedup_key) WHERE status <> 'resolved';
CREATE INDEX IF NOT EXISTS ix_alerts_tenant_status ON alerts (tenant_id, status, last_seen_at);

CREATE TABLE IF NOT EXISTS alert_channels (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('email','webhook')),
  target TEXT NOT NULL,
  secret_sealed BLOB,
  min_severity TEXT NOT NULL DEFAULT 'high' CHECK (min_severity IN ('low','medium','high','critical')),
  enabled INTEGER NOT NULL DEFAULT 1,
  created_by TEXT REFERENCES platform_users (id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (kind <> 'webhook' OR secret_sealed IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS ix_alert_channels_tenant ON alert_channels (tenant_id, enabled);

CREATE TABLE IF NOT EXISTS alert_deliveries (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  alert_id TEXT NOT NULL REFERENCES alerts (id),
  channel_id TEXT NOT NULL REFERENCES alert_channels (id),
  -- what was raised: 'raised' (new alert) or 'test'
  reason TEXT NOT NULL DEFAULT 'raised' CHECK (reason IN ('raised','test')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_error TEXT,
  sent_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_alert_deliveries_tenant_due ON alert_deliveries (tenant_id, status, next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_alert_deliveries_tenant_alert ON alert_deliveries (tenant_id, alert_id);

CREATE TABLE IF NOT EXISTS alert_cursors (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  last_seq INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_alert_rule_settings_xtenant_ins BEFORE INSERT ON alert_rule_settings
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: alert_rule_settings'); END;

CREATE TRIGGER IF NOT EXISTS tg_alert_rule_settings_xtenant_upd BEFORE UPDATE OF tenant_id, updated_by ON alert_rule_settings
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: alert_rule_settings'); END;

CREATE TRIGGER IF NOT EXISTS tg_alerts_xtenant_ins BEFORE INSERT ON alerts
WHEN (NEW.assignee_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.assignee_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.acknowledged_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.acknowledged_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.resolved_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.resolved_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: alerts'); END;

CREATE TRIGGER IF NOT EXISTS tg_alerts_xtenant_upd BEFORE UPDATE OF tenant_id, assignee_user_id, acknowledged_by, resolved_by ON alerts
WHEN (NEW.assignee_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.assignee_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.acknowledged_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.acknowledged_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.resolved_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.resolved_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: alerts'); END;

CREATE TRIGGER IF NOT EXISTS tg_alert_channels_xtenant_ins BEFORE INSERT ON alert_channels
WHEN NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: alert_channels'); END;

CREATE TRIGGER IF NOT EXISTS tg_alert_channels_xtenant_upd BEFORE UPDATE OF tenant_id, created_by ON alert_channels
WHEN NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: alert_channels'); END;

CREATE TRIGGER IF NOT EXISTS tg_alert_deliveries_xtenant_ins BEFORE INSERT ON alert_deliveries
WHEN EXISTS (SELECT 1 FROM alerts p WHERE p.id = NEW.alert_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM alert_channels p WHERE p.id = NEW.channel_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: alert_deliveries'); END;

CREATE TRIGGER IF NOT EXISTS tg_alert_deliveries_xtenant_upd BEFORE UPDATE OF tenant_id, alert_id, channel_id ON alert_deliveries
WHEN EXISTS (SELECT 1 FROM alerts p WHERE p.id = NEW.alert_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM alert_channels p WHERE p.id = NEW.channel_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: alert_deliveries'); END;
