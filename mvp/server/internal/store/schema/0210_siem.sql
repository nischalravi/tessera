-- SIEM sinks: push the audit ledger to a tenant's SIEM (issue #169).
--
-- A sink is a destination (kind 'syslog': RFC 5425 syslog over TLS to
-- host:port; 'webhook': an https URL, Splunk HEC or plain JSON for Sentinel
-- and log pipelines) and a format ('json': the hash-chained record of
-- /api/audit/export, whose hash a SIEM can recompute; 'ocsf': OCSF 1.3).
-- The credential (HEC or bearer token) is sealed under the KEK (AAD
-- siem_sinks.secret_sealed.<id>).
--
-- cursor_seq is the last audit seq the sink has acknowledged: delivery is at
-- least once, in seq order, and resumes there after a restart. A batch that
-- the destination rejects outright (a 4xx other than 408/429) for
-- max attempts is written to siem_dead_letters and skipped; everything else
-- retries with backoff until it succeeds.
CREATE TABLE IF NOT EXISTS siem_sinks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('syslog','webhook')),
  format TEXT NOT NULL CHECK (format IN ('json','ocsf')),
  target TEXT NOT NULL,
  -- webhook: 'hec' or 'json'; syslog: '' (RFC 5424 over RFC 5425 framing)
  flavor TEXT NOT NULL DEFAULT '',
  -- a PEM CA bundle for a syslog collector with a private CA
  ca_pem TEXT,
  secret_sealed BLOB,
  include_http INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  cursor_seq INTEGER NOT NULL DEFAULT 0 CHECK (cursor_seq >= 0),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  last_error TEXT,
  last_success_at TEXT,
  delivered_count INTEGER NOT NULL DEFAULT 0,
  dead_letter_count INTEGER NOT NULL DEFAULT 0,
  created_by TEXT REFERENCES platform_users (id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_siem_sinks_tenant ON siem_sinks (tenant_id, enabled);

CREATE TABLE IF NOT EXISTS siem_dead_letters (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sink_id TEXT NOT NULL REFERENCES siem_sinks (id),
  from_seq INTEGER NOT NULL,
  to_seq INTEGER NOT NULL,
  events INTEGER NOT NULL,
  error TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (from_seq <= to_seq)
);
CREATE INDEX IF NOT EXISTS ix_siem_dead_letters_tenant_sink ON siem_dead_letters (tenant_id, sink_id, created_at);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_siem_sinks_xtenant_ins BEFORE INSERT ON siem_sinks
WHEN NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: siem_sinks'); END;

CREATE TRIGGER IF NOT EXISTS tg_siem_sinks_xtenant_upd BEFORE UPDATE OF tenant_id, created_by ON siem_sinks
WHEN NEW.created_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.created_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: siem_sinks'); END;

CREATE TRIGGER IF NOT EXISTS tg_siem_dead_letters_xtenant_ins BEFORE INSERT ON siem_dead_letters
WHEN EXISTS (SELECT 1 FROM siem_sinks p WHERE p.id = NEW.sink_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: siem_dead_letters'); END;

CREATE TRIGGER IF NOT EXISTS tg_siem_dead_letters_xtenant_upd BEFORE UPDATE OF tenant_id, sink_id ON siem_dead_letters
WHEN EXISTS (SELECT 1 FROM siem_sinks p WHERE p.id = NEW.sink_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: siem_dead_letters'); END;
