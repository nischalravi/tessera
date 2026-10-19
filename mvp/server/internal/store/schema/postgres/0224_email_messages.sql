-- Postgres dialect of schema/0224_email_messages.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE email_messages (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  notification_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  recipient TEXT NOT NULL,
  subject TEXT NOT NULL,
  mail_from TEXT,
  rcpt_to TEXT,
  status TEXT NOT NULL CHECK (status IN ('queued','sending','accepted','deferred','rejected','failed','bounced')),
  queue_id TEXT,
  attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  attempts TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, notification_id),
  FOREIGN KEY (tenant_id, notification_id) REFERENCES notifications (tenant_id, id)
);

CREATE INDEX ix_email_messages_tenant_status ON email_messages (tenant_id, status, created_at);

