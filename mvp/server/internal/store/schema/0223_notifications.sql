-- Notifications (issue #189): a per-tenant outbox that is also the in-app
-- inbox.
--
-- A notification is written in the same transaction as the domain event that
-- causes it (a request submitted, an approval escalated, a review launched,
-- a grant about to expire), so a rolled-back event leaves none behind.
--
-- The recipient is a platform user (user_id: who sees it in the inbox) and/or
-- an identity that has no sign-in (identity_id, reached by email only);
-- recipient_email is the address at the time it was written. dedupe_key makes
-- a notification idempotent: the producer's event key plus the recipient, so
-- a retried event or a repeated scan never notifies twice.
--
-- in_app is 1 when the notification shows in the user's inbox; read_at is
-- when they read it. delivery is the email side: none (no email wanted),
-- pending (to send; attempts and next_attempt_at drive retries with
-- backoff), digest (waits for the daily digest) and digested (was in one),
-- sent, skipped (email is not configured or the recipient has no address)
-- and dead (a dead letter after too many attempts or a permanent failure).
-- Each send is an audit event.
--
-- notification_prefs is a user's choice per kind: off, in_app, email, both
-- or digest (in-app plus the daily digest email). Kinds that cannot be
-- turned off ignore off.
--
-- Tenant-owned: guard triggers at the end refuse references to another
-- tenant's rows.
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT REFERENCES platform_users (id),
  identity_id INTEGER REFERENCES identities (id),
  recipient_email TEXT,
  kind TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  link TEXT NOT NULL DEFAULT '',
  dedupe_key TEXT NOT NULL,
  in_app INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  read_at TEXT,
  delivery TEXT NOT NULL CHECK (delivery IN ('none','pending','digest','digested','sent','skipped','dead')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at TEXT,
  last_error TEXT,
  sent_at TEXT,
  CHECK (user_id IS NOT NULL OR identity_id IS NOT NULL OR recipient_email IS NOT NULL),
  UNIQUE (tenant_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS ix_notifications_tenant_user ON notifications (tenant_id, user_id, created_at);
CREATE INDEX IF NOT EXISTS ix_notifications_tenant_delivery ON notifications (tenant_id, delivery, next_attempt_at);

CREATE TABLE IF NOT EXISTS notification_prefs (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  kind TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('off','in_app','email','both','digest')),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_id, kind)
);

-- Cross-tenant reference guards (same pattern as 0205_requests.sql).

CREATE TRIGGER IF NOT EXISTS tg_notifications_xtenant_ins BEFORE INSERT ON notifications
WHEN (NEW.user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: notifications'); END;

CREATE TRIGGER IF NOT EXISTS tg_notifications_xtenant_upd BEFORE UPDATE OF tenant_id, user_id, identity_id ON notifications
WHEN (NEW.user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: notifications'); END;

CREATE TRIGGER IF NOT EXISTS tg_notification_prefs_xtenant_ins BEFORE INSERT ON notification_prefs
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: notification_prefs'); END;

CREATE TRIGGER IF NOT EXISTS tg_notification_prefs_xtenant_upd BEFORE UPDATE OF tenant_id, user_id ON notification_prefs
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: notification_prefs'); END;
