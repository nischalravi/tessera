-- Postgres dialect of schema/0008_admin_changes.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE tenant_recoveries (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  invitation_id TEXT NOT NULL,
  operator TEXT NOT NULL CHECK (length(operator) BETWEEN 1 AND 200),
  co_operator TEXT NOT NULL CHECK (length(co_operator) BETWEEN 1 AND 200),
  ticket TEXT NOT NULL CHECK (length(ticket) BETWEEN 1 AND 200),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','cancelled','completed')),
  not_before TEXT NOT NULL,
  created_at TEXT NOT NULL,
  cancelled_by_user_id TEXT,
  cancelled_at TEXT,
  completed_by_user_id TEXT,
  completed_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, invitation_id),
  CHECK (operator <> co_operator),
  CHECK (created_at < not_before),
  CHECK ((status = 'cancelled') = (cancelled_at IS NOT NULL)),
  CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
  FOREIGN KEY (tenant_id, invitation_id) REFERENCES bootstrap_invitations (tenant_id, id),
  FOREIGN KEY (tenant_id, cancelled_by_user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, completed_by_user_id) REFERENCES platform_users (tenant_id, id)
);

CREATE INDEX tenant_recoveries_tenant ON tenant_recoveries(tenant_id);
CREATE UNIQUE INDEX tenant_recoveries_one_pending ON tenant_recoveries(tenant_id) WHERE status = 'pending';

CREATE TABLE admin_change_requests (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  type TEXT NOT NULL CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update')),
  payload TEXT NOT NULL CHECK (payload IS JSON OBJECT),
  payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
  secret_enc BYTEA,
  target_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending_approval','cooling_off','applied','rejected','cancelled','expired','failed')),
  two_person BIGINT NOT NULL CHECK (two_person IN (0, 1)),
  cooling_off_seconds BIGINT NOT NULL CHECK (cooling_off_seconds >= 0),
  requested_by_user_id TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  approved_by_user_id TEXT,
  approved_at TEXT,
  effective_at TEXT,
  decided_by_user_id TEXT,
  decided_at TEXT,
  applied_at TEXT,
  failure TEXT,
  test_login_at TEXT,
  UNIQUE (tenant_id, id),
  CHECK (requested_at < expires_at),
  CHECK (approved_by_user_id IS NULL OR approved_by_user_id <> requested_by_user_id),
  CHECK (two_person = 0 OR status NOT IN ('cooling_off','applied') OR approved_by_user_id IS NOT NULL),
  CHECK (status NOT IN ('cooling_off','applied') OR effective_at IS NOT NULL),
  CHECK ((status IN ('rejected','cancelled')) = (decided_by_user_id IS NOT NULL)),
  FOREIGN KEY (tenant_id, requested_by_user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by_user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by_user_id) REFERENCES platform_users (tenant_id, id)
);

CREATE INDEX admin_change_requests_tenant ON admin_change_requests(tenant_id, status, requested_at);

CREATE TABLE admin_notifications (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  change_request_id TEXT,
  recovery_id TEXT,
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 100),
  recipient_type TEXT NOT NULL CHECK (recipient_type IN ('admin','contact','operator')),
  recipient_user_id TEXT,
  recipient_address TEXT,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 300),
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  UNIQUE (tenant_id, dedupe_key),
  CHECK ((recipient_type = 'admin') = (recipient_user_id IS NOT NULL)),
  CHECK (recipient_type = 'admin' OR recipient_address IS NOT NULL),
  FOREIGN KEY (tenant_id, change_request_id) REFERENCES admin_change_requests (tenant_id, id),
  FOREIGN KEY (tenant_id, recovery_id) REFERENCES tenant_recoveries (tenant_id, id),
  FOREIGN KEY (tenant_id, recipient_user_id) REFERENCES platform_users (tenant_id, id)
);

CREATE INDEX admin_notifications_tenant ON admin_notifications(tenant_id, created_at);

-- A recovery naming another tenant's invitation is refused as a cross-tenant
-- reference before the one-pending unique index can answer first (SQLite's
-- BEFORE trigger order; the composite foreign key above still backs it).
CREATE TRIGGER tg_tenant_recoveries_invitation_xtenant BEFORE INSERT OR UPDATE OF tenant_id, invitation_id ON tenant_recoveries
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('bootstrap_invitations', 'invitation_id', 'text');
