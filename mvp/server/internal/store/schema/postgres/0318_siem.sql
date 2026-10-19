-- Postgres dialect of schema/0210_siem.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql. created_by is a soft
-- reference like SQLite's trigger: another tenant's id is refused, an unknown one is tolerated.

-- +goose Up

CREATE TABLE siem_sinks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('syslog','webhook')),
  format TEXT NOT NULL CHECK (format IN ('json','ocsf')),
  target TEXT NOT NULL,
  flavor TEXT NOT NULL DEFAULT '',
  ca_pem TEXT,
  secret_sealed BYTEA,
  include_http BIGINT NOT NULL DEFAULT 0,
  enabled BIGINT NOT NULL DEFAULT 1,
  cursor_seq BIGINT NOT NULL DEFAULT 0 CHECK (cursor_seq >= 0),
  attempts BIGINT NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  last_error TEXT,
  last_success_at TEXT,
  delivered_count BIGINT NOT NULL DEFAULT 0,
  dead_letter_count BIGINT NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, id)
);
CREATE INDEX ix_siem_sinks_tenant ON siem_sinks (tenant_id, enabled);

CREATE TABLE siem_dead_letters (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sink_id TEXT NOT NULL,
  from_seq BIGINT NOT NULL,
  to_seq BIGINT NOT NULL,
  events BIGINT NOT NULL,
  error TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (from_seq <= to_seq),
  FOREIGN KEY (tenant_id, sink_id) REFERENCES siem_sinks (tenant_id, id)
);
CREATE INDEX ix_siem_dead_letters_tenant_sink ON siem_dead_letters (tenant_id, sink_id, created_at);

CREATE TRIGGER tg_siem_sinks_created_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, created_by ON siem_sinks
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'created_by', 'text');
