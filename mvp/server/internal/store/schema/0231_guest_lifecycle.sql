-- Guest lifecycle: reminders, renewal requests and step-up, sponsor-leaver
-- transfer tasks, conversion tasks, deprovisioning stages and the tenant's
-- lifecycle settings (guest accounts design §8, issue #74 / GU-11).
--
-- guest_lifecycle_settings are the tenant's defaults for everything below
-- (reminder days, the transfer deadline, end or suspend on a sponsor's
-- departure, the grace period per population, the retention periods, whether
-- identifier hashes survive the purge). The row is optional; the code supplies
-- the design's defaults.
--
-- guest_reminders is the memory of the reminder job: one row per
-- (sponsorship, end date, audience, threshold), so a reminder goes out once
-- across sweeps and restarts. A renewal moves the end date and so re-arms them.
--
-- guest_renewal_tokens is the guest's "request renewal" link: single use, only
-- the SHA-256 of the token is stored, bound to the sponsorship and the guest.
--
-- guest_lifecycle_tasks are the Inbox tasks of the lifecycle: a sponsor's
-- departure asks someone to take over a sponsorship before a deadline
-- (sponsor_transfer), a guest asks for a renewal (renewal_request), a hire asks
-- the sponsor whether a contractor stays on as one (dual_status). One open task
-- per sponsorship and kind.
--
-- sponsorship_stepups is a renewal that waits for the guest's identity
-- assurance to reach what the bundle now needs: recorded, not applied, until the
-- IAL is met (the sponsorship's access does not extend meanwhile).
--
-- guest_deprovisioning is where a person stands after their last affiliation
-- ended: in 'grace' (accounts disabled, access ended), 'deprovisioned' once the
-- grace period passed, 'purged' once the retention period passed and the
-- operational PII was reduced to a tombstone, or 'returned' when they came back
-- (a later end starts a new cycle on the same row).
-- The audit ledger is never touched.
--
-- Tenant-owned like 0001_tenancy.sql: guard triggers at the end refuse a
-- reference to another tenant's row. Created with IF NOT EXISTS; a reseed
-- drops and recreates (store.tables).

CREATE TABLE IF NOT EXISTS guest_lifecycle_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  sponsor_reminder_days TEXT NOT NULL DEFAULT '[30,14,3]' CHECK (json_valid(sponsor_reminder_days)),
  guest_reminder_days INTEGER NOT NULL DEFAULT 14 CHECK (guest_reminder_days BETWEEN 0 AND 365),
  transfer_deadline_days INTEGER NOT NULL DEFAULT 14 CHECK (transfer_deadline_days BETWEEN 1 AND 90),
  on_sponsor_departure TEXT NOT NULL DEFAULT 'end' CHECK (on_sponsor_departure IN ('end','suspend')),
  conversion_dual_status TEXT NOT NULL DEFAULT 'end' CHECK (conversion_dual_status IN ('end','sponsor_confirms')),
  grace_days_visitor INTEGER NOT NULL DEFAULT 0 CHECK (grace_days_visitor BETWEEN 0 AND 365),
  grace_days_contractor INTEGER NOT NULL DEFAULT 30 CHECK (grace_days_contractor BETWEEN 0 AND 365),
  grace_days_volunteer INTEGER NOT NULL DEFAULT 30 CHECK (grace_days_volunteer BETWEEN 0 AND 365),
  grace_days_partner INTEGER NOT NULL DEFAULT 30 CHECK (grace_days_partner BETWEEN 0 AND 365),
  retention_days INTEGER NOT NULL DEFAULT 2555 CHECK (retention_days BETWEEN 1 AND 36500),
  retention_days_visitor INTEGER NOT NULL DEFAULT 365 CHECK (retention_days_visitor BETWEEN 1 AND 36500),
  keep_rematch_hashes INTEGER NOT NULL DEFAULT 0 CHECK (keep_rematch_hashes IN (0,1)),
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS guest_reminders (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsorship_id TEXT NOT NULL REFERENCES sponsorships (id),
  ends_at TEXT NOT NULL,
  audience TEXT NOT NULL CHECK (audience IN ('sponsor','guest')),
  threshold_days INTEGER NOT NULL CHECK (threshold_days > 0),
  sent_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, sponsorship_id, ends_at, audience, threshold_days)
);

CREATE TABLE IF NOT EXISTS guest_renewal_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsorship_id TEXT NOT NULL REFERENCES sponsorships (id),
  guest_identity_id INTEGER NOT NULL REFERENCES identities (id),
  token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
  status TEXT NOT NULL CHECK (status IN ('issued','used','revoked','expired')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  used_at TEXT,
  CHECK ((status = 'used') = (used_at IS NOT NULL)),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX IF NOT EXISTS ix_guest_renewal_tokens_sponsorship ON guest_renewal_tokens (tenant_id, sponsorship_id, status);

CREATE TABLE IF NOT EXISTS guest_lifecycle_tasks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (kind IN ('sponsor_transfer','renewal_request','dual_status')),
  sponsorship_id TEXT NOT NULL REFERENCES sponsorships (id),
  subject_identity_id INTEGER NOT NULL REFERENCES identities (id),
  trigger TEXT NOT NULL CHECK (trigger IN ('leaver','mover','ineligible','guest_request','conversion')),
  status TEXT NOT NULL CHECK (status IN ('open','done','declined','expired','cancelled')),
  deadline TEXT,
  outcome TEXT CHECK (outcome IN ('transferred','ended','suspended','renewed','dismissed','confirmed')),
  note TEXT,
  resolved_by TEXT REFERENCES platform_users (id),
  resolved_at TEXT,
  created_at TEXT NOT NULL,
  CHECK ((status = 'open') = (resolved_at IS NULL)),
  CHECK ((status = 'open') = (outcome IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_guest_lifecycle_tasks_open ON guest_lifecycle_tasks (tenant_id, sponsorship_id, kind) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS ix_guest_lifecycle_tasks_status ON guest_lifecycle_tasks (tenant_id, status, deadline);

CREATE TABLE IF NOT EXISTS sponsorship_stepups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsorship_id TEXT NOT NULL REFERENCES sponsorships (id),
  requested_ends_at TEXT NOT NULL,
  justification TEXT NOT NULL CHECK (justification <> ''),
  required_ial INTEGER NOT NULL CHECK (required_ial IN (1,2)),
  status TEXT NOT NULL CHECK (status IN ('pending','applied','cancelled')),
  requested_by TEXT REFERENCES platform_users (id),
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  CHECK ((status = 'pending') = (resolved_at IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sponsorship_stepups_pending ON sponsorship_stepups (tenant_id, sponsorship_id) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS guest_deprovisioning (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  population TEXT NOT NULL CHECK (population IN ('visitor','contractor','volunteer','partner')),
  stage TEXT NOT NULL CHECK (stage IN ('grace','deprovisioned','purged','returned')),
  held_access INTEGER NOT NULL CHECK (held_access IN (0,1)),
  ended_at TEXT NOT NULL,
  grace_until TEXT NOT NULL,
  retention_until TEXT NOT NULL,
  deprovisioned_at TEXT,
  purged_at TEXT,
  returned_at TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, identity_id),
  CHECK ((stage = 'purged') = (purged_at IS NOT NULL)),
  CHECK ((stage = 'returned') = (returned_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS ix_guest_deprovisioning_stage ON guest_deprovisioning (tenant_id, stage, grace_until);

-- Reminders are a ledger: never changed, never removed.
CREATE TRIGGER IF NOT EXISTS tg_guest_reminders_no_update BEFORE UPDATE ON guest_reminders
BEGIN SELECT RAISE(ABORT, 'guest_reminders is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_reminders_no_delete BEFORE DELETE ON guest_reminders
BEGIN SELECT RAISE(ABORT, 'guest_reminders is append-only'); END;

-- A task's subject and sponsorship never change and a resolved task is final.
CREATE TRIGGER IF NOT EXISTS tg_guest_lifecycle_tasks_immutable BEFORE UPDATE ON guest_lifecycle_tasks
WHEN OLD.status <> 'open' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.kind <> OLD.kind
	OR NEW.sponsorship_id <> OLD.sponsorship_id OR NEW.subject_identity_id <> OLD.subject_identity_id
	OR NEW.trigger <> OLD.trigger OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'guest_lifecycle_tasks: resolved rows and identity columns are immutable'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_lifecycle_tasks_no_delete BEFORE DELETE ON guest_lifecycle_tasks
BEGIN SELECT RAISE(ABORT, 'guest_lifecycle_tasks are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_guest_renewal_tokens_immutable BEFORE UPDATE ON guest_renewal_tokens
WHEN OLD.status <> 'issued' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsorship_id <> OLD.sponsorship_id
	OR NEW.guest_identity_id <> OLD.guest_identity_id OR NEW.token_hash <> OLD.token_hash OR NEW.expires_at <> OLD.expires_at
	OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'guest_renewal_tokens: spent rows and identity columns are immutable'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_renewal_tokens_no_delete BEFORE DELETE ON guest_renewal_tokens
BEGIN SELECT RAISE(ABORT, 'guest_renewal_tokens are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_sponsorship_stepups_immutable BEFORE UPDATE ON sponsorship_stepups
WHEN OLD.status <> 'pending' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsorship_id <> OLD.sponsorship_id
	OR NEW.requested_ends_at <> OLD.requested_ends_at OR NEW.justification <> OLD.justification
	OR NEW.required_ial <> OLD.required_ial OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'sponsorship_stepups: resolved rows and identity columns are immutable'); END;
CREATE TRIGGER IF NOT EXISTS tg_sponsorship_stepups_no_delete BEFORE DELETE ON sponsorship_stepups
BEGIN SELECT RAISE(ABORT, 'sponsorship_stepups are append-only'); END;

-- A person's stage only moves forward, and a purge is final. A person who
-- returned starts a new cycle when their next affiliation ends: 'returned' goes
-- back to 'grace' with the new dates, and only that.
CREATE TRIGGER IF NOT EXISTS tg_guest_deprovisioning_immutable BEFORE UPDATE ON guest_deprovisioning
WHEN OLD.stage = 'purged' OR NEW.tenant_id <> OLD.tenant_id OR NEW.identity_id <> OLD.identity_id
	OR (OLD.stage = 'returned' AND NEW.stage <> 'grace')
	OR (OLD.stage <> 'returned' AND NEW.ended_at <> OLD.ended_at)
	OR (OLD.stage = 'deprovisioned' AND NEW.stage = 'grace')
BEGIN SELECT RAISE(ABORT, 'guest_deprovisioning: final rows and identity columns are immutable'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_deprovisioning_no_delete BEFORE DELETE ON guest_deprovisioning
BEGIN SELECT RAISE(ABORT, 'guest_deprovisioning is append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_guest_lifecycle_settings_xtenant_ins BEFORE INSERT ON guest_lifecycle_settings
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_lifecycle_settings'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_lifecycle_settings_xtenant_upd BEFORE UPDATE OF tenant_id, updated_by ON guest_lifecycle_settings
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_lifecycle_settings'); END;

CREATE TRIGGER IF NOT EXISTS tg_guest_reminders_xtenant_ins BEFORE INSERT ON guest_reminders
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_reminders'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_reminders_xtenant_upd BEFORE UPDATE OF tenant_id, sponsorship_id ON guest_reminders
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_reminders'); END;

CREATE TRIGGER IF NOT EXISTS tg_guest_renewal_tokens_xtenant_ins BEFORE INSERT ON guest_renewal_tokens
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.guest_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_renewal_tokens'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_renewal_tokens_xtenant_upd BEFORE UPDATE OF tenant_id, sponsorship_id, guest_identity_id ON guest_renewal_tokens
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.guest_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_renewal_tokens'); END;

CREATE TRIGGER IF NOT EXISTS tg_guest_lifecycle_tasks_xtenant_ins BEFORE INSERT ON guest_lifecycle_tasks
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.subject_identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.resolved_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.resolved_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_lifecycle_tasks'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_lifecycle_tasks_xtenant_upd BEFORE UPDATE OF tenant_id, sponsorship_id, subject_identity_id, resolved_by ON guest_lifecycle_tasks
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.subject_identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.resolved_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.resolved_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_lifecycle_tasks'); END;

CREATE TRIGGER IF NOT EXISTS tg_sponsorship_stepups_xtenant_ins BEFORE INSERT ON sponsorship_stepups
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.requested_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sponsorship_stepups'); END;
CREATE TRIGGER IF NOT EXISTS tg_sponsorship_stepups_xtenant_upd BEFORE UPDATE OF tenant_id, sponsorship_id, requested_by ON sponsorship_stepups
WHEN EXISTS (SELECT 1 FROM sponsorships p WHERE p.id = NEW.sponsorship_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.requested_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sponsorship_stepups'); END;

CREATE TRIGGER IF NOT EXISTS tg_guest_deprovisioning_xtenant_ins BEFORE INSERT ON guest_deprovisioning
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_deprovisioning'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_deprovisioning_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON guest_deprovisioning
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_deprovisioning'); END;
