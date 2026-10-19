-- Postgres dialect of schema/0209_alerts.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql. The platform_users columns are
-- soft references like SQLite's triggers: another tenant's id is refused, an unknown one is tolerated.

-- +goose Up

CREATE TABLE alert_rule_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  rule_id TEXT NOT NULL,
  enabled BIGINT NOT NULL DEFAULT 1,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  threshold BIGINT NOT NULL CHECK (threshold BETWEEN 1 AND 10000),
  window_minutes BIGINT NOT NULL CHECK (window_minutes BETWEEN 1 AND 10080),
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, rule_id)
);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  rule_id TEXT NOT NULL,
  dedup_key TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved')),
  count BIGINT NOT NULL DEFAULT 1,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_event_seq BIGINT,
  assignee_user_id TEXT,
  acknowledged_by TEXT,
  acknowledged_at TEXT,
  resolved_by TEXT,
  resolved_at TEXT,
  resolution TEXT,
  UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX ux_alerts_tenant_live ON alerts (tenant_id, rule_id, dedup_key) WHERE status <> 'resolved';
CREATE INDEX ix_alerts_tenant_status ON alerts (tenant_id, status, last_seen_at);

CREATE TABLE alert_channels (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('email','webhook')),
  target TEXT NOT NULL,
  secret_sealed BYTEA,
  min_severity TEXT NOT NULL DEFAULT 'high' CHECK (min_severity IN ('low','medium','high','critical')),
  enabled BIGINT NOT NULL DEFAULT 1,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (kind <> 'webhook' OR secret_sealed IS NOT NULL),
  UNIQUE (tenant_id, id)
);
CREATE INDEX ix_alert_channels_tenant ON alert_channels (tenant_id, enabled);

CREATE TABLE alert_deliveries (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  alert_id TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT 'raised' CHECK (reason IN ('raised','test')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
  attempts BIGINT NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_error TEXT,
  sent_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, alert_id) REFERENCES alerts (tenant_id, id),
  FOREIGN KEY (tenant_id, channel_id) REFERENCES alert_channels (tenant_id, id)
);
CREATE INDEX ix_alert_deliveries_tenant_due ON alert_deliveries (tenant_id, status, next_attempt_at);
CREATE INDEX ix_alert_deliveries_tenant_alert ON alert_deliveries (tenant_id, alert_id);

CREATE TABLE alert_cursors (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  last_seq BIGINT NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TRIGGER tg_alert_rule_settings_updated_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, updated_by ON alert_rule_settings
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'updated_by', 'text');
CREATE TRIGGER tg_alerts_assignee_user_id_xtenant BEFORE INSERT OR UPDATE OF tenant_id, assignee_user_id ON alerts
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'assignee_user_id', 'text');
CREATE TRIGGER tg_alerts_acknowledged_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, acknowledged_by ON alerts
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'acknowledged_by', 'text');
CREATE TRIGGER tg_alerts_resolved_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, resolved_by ON alerts
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'resolved_by', 'text');
CREATE TRIGGER tg_alert_channels_created_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, created_by ON alert_channels
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'created_by', 'text');
