-- Email delivery log (issue #189): one record per email the dispatcher sends,
-- with the SMTP transaction of every attempt, so an operator can see what
-- happened to a message without the relay's own dashboard.
--
-- Subject and recipient are kept; the body never is. attempts is a JSON array,
-- one entry per attempt: times, the relay's banner and capabilities, the
-- STARTTLS result, and every command with its reply (AUTH credentials are
-- recorded as <redacted>; the transcript is size-capped).
--
-- status: queued (waiting for an attempt), sending, accepted (the relay
-- answered 250 at the end of DATA: accepted by the relay, not delivered to
-- the inbox), deferred (4xx: retried with backoff), rejected (5xx: not
-- retried), failed (network or TLS error: retried with backoff) and bounced
-- (reserved for bounce and DSN processing, a later step; nothing sets it yet).
-- queue_id is the relay's queue id parsed from the final 250 reply.
CREATE TABLE IF NOT EXISTS email_messages (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  notification_id TEXT NOT NULL REFERENCES notifications (id),
  kind TEXT NOT NULL,
  recipient TEXT NOT NULL,
  subject TEXT NOT NULL,
  mail_from TEXT,
  rcpt_to TEXT,
  status TEXT NOT NULL CHECK (status IN ('queued','sending','accepted','deferred','rejected','failed','bounced')),
  queue_id TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  attempts TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, notification_id)
);
CREATE INDEX IF NOT EXISTS ix_email_messages_tenant_status ON email_messages (tenant_id, status, created_at);

CREATE TRIGGER IF NOT EXISTS tg_email_messages_xtenant_ins BEFORE INSERT ON email_messages
WHEN EXISTS (SELECT 1 FROM notifications p WHERE p.id = NEW.notification_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: email_messages'); END;

CREATE TRIGGER IF NOT EXISTS tg_email_messages_xtenant_upd BEFORE UPDATE OF tenant_id, notification_id ON email_messages
WHEN EXISTS (SELECT 1 FROM notifications p WHERE p.id = NEW.notification_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: email_messages'); END;
