-- Postgres dialect of schema/0223_notifications.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE notifications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT,
  identity_id BIGINT,
  recipient_email TEXT,
  kind TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  link TEXT NOT NULL DEFAULT '',
  dedupe_key TEXT NOT NULL,
  in_app BIGINT NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  read_at TEXT,
  delivery TEXT NOT NULL CHECK (delivery IN ('none','pending','digest','digested','sent','skipped','dead')),
  attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at TEXT,
  last_error TEXT,
  sent_at TEXT,
  CHECK (user_id IS NOT NULL OR identity_id IS NOT NULL OR recipient_email IS NOT NULL),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, dedupe_key),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);

CREATE INDEX ix_notifications_tenant_user ON notifications (tenant_id, user_id, created_at);
CREATE INDEX ix_notifications_tenant_delivery ON notifications (tenant_id, delivery, next_attempt_at);

CREATE TABLE notification_prefs (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('off','in_app','email','both','digest')),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_id, kind),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id)
);

-- Columns that name a user (or an edge that may expire) but are not foreign keys: SQLite never
-- enforced them, and they hold display strings or ids of rows that may be gone. The guard refuses an
-- id that belongs to ANOTHER tenant and tolerates one that does not exist (tessera_guard_soft_ref).
CREATE TRIGGER tg_notifications_user_id_xtenant BEFORE INSERT OR UPDATE OF tenant_id, user_id ON notifications
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'user_id', 'text');
