-- Phase 0 PR12: admin-change workflow, admin notifications and operator
-- recovery (design §15, §19 PR12).
--
-- Every table is tenant-owned: tenant_id references tenants(id), every UNIQUE
-- constraint starts with tenant_id, and the guard triggers at the end refuse a
-- reference to another tenant's row. UUID text primary keys; RFC 3339 UTC
-- timestamps with microseconds (store.RT).
--
-- admin_notifications is NOT the general notification outbox of issue #189
-- (a table named notifications): it holds only what this workflow must tell
-- tenant admins, security contacts and operators, so the two can merge later
-- (see the PR description).

-- tenant_recoveries: one operator-assisted recovery (§15.5). The invitation it
-- names is an ordinary bootstrap invitation that must not be redeemed before
-- not_before (72 h after the request) and only while the recovery is pending.
CREATE TABLE IF NOT EXISTS tenant_recoveries (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  invitation_id TEXT NOT NULL REFERENCES bootstrap_invitations (id),
  operator TEXT NOT NULL CHECK (length(operator) BETWEEN 1 AND 200),
  co_operator TEXT NOT NULL CHECK (length(co_operator) BETWEEN 1 AND 200),
  ticket TEXT NOT NULL CHECK (length(ticket) BETWEEN 1 AND 200),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','cancelled','completed')),
  not_before TEXT NOT NULL,
  created_at TEXT NOT NULL,
  cancelled_by_user_id TEXT REFERENCES platform_users (id), cancelled_at TEXT,
  completed_by_user_id TEXT REFERENCES platform_users (id), completed_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, invitation_id),
  -- two different operators (§15.5 step 2)
  CHECK (operator <> co_operator),
  CHECK (created_at < not_before),
  CHECK ((status = 'cancelled') = (cancelled_at IS NOT NULL)),
  CHECK ((status = 'completed') = (completed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS tenant_recoveries_tenant ON tenant_recoveries(tenant_id);
-- at most one recovery in flight per tenant
CREATE UNIQUE INDEX IF NOT EXISTS tenant_recoveries_one_pending ON tenant_recoveries(tenant_id) WHERE status = 'pending';

-- admin_change_requests: the two-person, step-up, cooling-off workflow of
-- §15.2. payload is the canonical JSON of the typed payload; payload_hash is
-- its SHA-256, which the approver must echo. secret_enc is the sealed client
-- secret of an idp_connection.create (never part of the payload or its hash);
-- every terminal transition clears it.
CREATE TABLE IF NOT EXISTS admin_change_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  type TEXT NOT NULL CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke',
    -- issue #53, GR-10: a SQL loader's creation or change (internal/admin/change_loader.go)
    'groups.loader.save',
    -- issue #298: per-tenant log retention settings (internal/admin/change_retention.go)
    'retention.update',
    -- deleting a folder with everything in it needs a second admin when it is large or populated (internal/admin/change_folder.go)
    'groups.folder.delete_recursive',
    -- deletion threshold guard settings: loosening takes two admins (internal/admin/change_deleteguard.go)
    'deletion_guard.update',
    -- a SIEM sink's event filter: narrowing it takes two admins (internal/admin/change_siem.go)
    'siem.sink.filter',
    -- moving a SIEM sink to another destination takes two admins (internal/admin/change_siem.go, issue #520)
    'siem.sink.target',
    -- loosening a security alert rule (disable, raise the threshold, lower the severity, shorten the window) takes two admins
    -- (internal/admin/change_alerts.go, issue #521)
    'alerts.rule.loosen',
    -- attesting a manual item of a vendor breach plan takes two admins (internal/admin/change_breach.go, issue #538)
    'breach.item.attest',
    -- enabling write-back on a provisioning target takes two admins (internal/admin/change_provision.go, issue #569)
    'provisioning.write_back.enable',
    -- changing the least-privilege loop's mode, caps or kill switch: loosening takes two admins (internal/admin/change_lp.go, issue #661)
    'lp.settings.update')),

  payload TEXT NOT NULL CHECK (json_valid(payload) AND json_type(payload) = 'object'),
  payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
  secret_enc BLOB,
  target_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending_approval','cooling_off','applied','rejected','cancelled','expired','failed')),
  two_person INTEGER NOT NULL CHECK (two_person IN (0, 1)),
  cooling_off_seconds INTEGER NOT NULL CHECK (cooling_off_seconds >= 0),
  requested_by_user_id TEXT NOT NULL REFERENCES platform_users (id),
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  approved_by_user_id TEXT REFERENCES platform_users (id), approved_at TEXT,
  effective_at TEXT,
  decided_by_user_id TEXT REFERENCES platform_users (id), decided_at TEXT,
  applied_at TEXT, failure TEXT,
  -- idp_connection.create: the requester's successful test login (§15.2)
  test_login_at TEXT,
  UNIQUE (tenant_id, id),
  CHECK (requested_at < expires_at),
  -- two people: the approver is never the requester (§15.1)
  CHECK (approved_by_user_id IS NULL OR approved_by_user_id <> requested_by_user_id),
  -- a two-person change cannot be applied without an approver
  CHECK (two_person = 0 OR status NOT IN ('cooling_off','applied') OR approved_by_user_id IS NOT NULL),
  CHECK (status NOT IN ('cooling_off','applied') OR effective_at IS NOT NULL),
  CHECK ((status IN ('rejected','cancelled')) = (decided_by_user_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS admin_change_requests_tenant ON admin_change_requests(tenant_id, status, requested_at);

-- admin_notifications: the notification queued for every transition (§15.2)
-- and every recovery step (§15.5). One row per recipient; dedupe_key makes a
-- retried transition idempotent. delivered_at stays NULL until a delivery
-- channel (issue #189's outbox) sends it.
CREATE TABLE IF NOT EXISTS admin_notifications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  change_request_id TEXT REFERENCES admin_change_requests (id),
  recovery_id TEXT REFERENCES tenant_recoveries (id),
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 100),
  recipient_type TEXT NOT NULL CHECK (recipient_type IN ('admin','contact','operator')),
  recipient_user_id TEXT REFERENCES platform_users (id),
  recipient_address TEXT,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 300),
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  UNIQUE (tenant_id, dedupe_key),
  CHECK ((recipient_type = 'admin') = (recipient_user_id IS NOT NULL)),
  CHECK (recipient_type = 'admin' OR recipient_address IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS admin_notifications_tenant ON admin_notifications(tenant_id, created_at);

-- ---------------------------------------------------------------- guard triggers

CREATE TRIGGER IF NOT EXISTS tg_tenant_recoveries_xtenant_ins BEFORE INSERT ON tenant_recoveries
WHEN EXISTS (SELECT 1 FROM bootstrap_invitations p WHERE p.id = NEW.invitation_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.cancelled_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.cancelled_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.completed_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.completed_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: tenant_recoveries'); END;

CREATE TRIGGER IF NOT EXISTS tg_tenant_recoveries_xtenant_upd BEFORE UPDATE OF tenant_id, invitation_id, cancelled_by_user_id, completed_by_user_id ON tenant_recoveries
WHEN EXISTS (SELECT 1 FROM bootstrap_invitations p WHERE p.id = NEW.invitation_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.cancelled_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.cancelled_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.completed_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.completed_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: tenant_recoveries'); END;

CREATE TRIGGER IF NOT EXISTS tg_admin_change_requests_xtenant_ins BEFORE INSERT ON admin_change_requests
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.approved_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.approved_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_change_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_admin_change_requests_xtenant_upd BEFORE UPDATE OF tenant_id, requested_by_user_id, approved_by_user_id, decided_by_user_id ON admin_change_requests
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.approved_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.approved_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_change_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_admin_notifications_xtenant_ins BEFORE INSERT ON admin_notifications
WHEN (NEW.change_request_id IS NOT NULL AND EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_request_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.recovery_id IS NOT NULL AND EXISTS (SELECT 1 FROM tenant_recoveries p WHERE p.id = NEW.recovery_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.recipient_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.recipient_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_notifications'); END;

CREATE TRIGGER IF NOT EXISTS tg_admin_notifications_xtenant_upd BEFORE UPDATE OF tenant_id, change_request_id, recovery_id, recipient_user_id ON admin_notifications
WHEN (NEW.change_request_id IS NOT NULL AND EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_request_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.recovery_id IS NOT NULL AND EXISTS (SELECT 1 FROM tenant_recoveries p WHERE p.id = NEW.recovery_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.recipient_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.recipient_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_notifications'); END;
