-- Postgres dialect of schema/0371_guest_lifecycle.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres; json_valid CHECKs are dropped: the column is TEXT and the store writes JSON). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE guest_lifecycle_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  sponsor_reminder_days TEXT NOT NULL DEFAULT '[30,14,3]',
  guest_reminder_days BIGINT NOT NULL DEFAULT 14 CHECK (guest_reminder_days BETWEEN 0 AND 365),
  transfer_deadline_days BIGINT NOT NULL DEFAULT 14 CHECK (transfer_deadline_days BETWEEN 1 AND 90),
  on_sponsor_departure TEXT NOT NULL DEFAULT 'end' CHECK (on_sponsor_departure IN ('end','suspend')),
  conversion_dual_status TEXT NOT NULL DEFAULT 'end' CHECK (conversion_dual_status IN ('end','sponsor_confirms')),
  grace_days_visitor BIGINT NOT NULL DEFAULT 0 CHECK (grace_days_visitor BETWEEN 0 AND 365),
  grace_days_contractor BIGINT NOT NULL DEFAULT 30 CHECK (grace_days_contractor BETWEEN 0 AND 365),
  grace_days_volunteer BIGINT NOT NULL DEFAULT 30 CHECK (grace_days_volunteer BETWEEN 0 AND 365),
  grace_days_partner BIGINT NOT NULL DEFAULT 30 CHECK (grace_days_partner BETWEEN 0 AND 365),
  retention_days BIGINT NOT NULL DEFAULT 2555 CHECK (retention_days BETWEEN 1 AND 36500),
  retention_days_visitor BIGINT NOT NULL DEFAULT 365 CHECK (retention_days_visitor BETWEEN 1 AND 36500),
  keep_rematch_hashes BIGINT NOT NULL DEFAULT 0 CHECK (keep_rematch_hashes IN (0,1)),
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, updated_by) REFERENCES platform_users (tenant_id, id)
);

CREATE TABLE guest_reminders (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsorship_id TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  audience TEXT NOT NULL CHECK (audience IN ('sponsor','guest')),
  threshold_days BIGINT NOT NULL CHECK (threshold_days > 0),
  sent_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, sponsorship_id, ends_at, audience, threshold_days),
  FOREIGN KEY (tenant_id, sponsorship_id) REFERENCES sponsorships (tenant_id, id)
);

CREATE TABLE guest_renewal_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsorship_id TEXT NOT NULL,
  guest_identity_id BIGINT NOT NULL,
  token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
  status TEXT NOT NULL CHECK (status IN ('issued','used','revoked','expired')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  used_at TEXT,
  CHECK ((status = 'used') = (used_at IS NOT NULL)),
  UNIQUE (tenant_id, token_hash),
  FOREIGN KEY (tenant_id, sponsorship_id) REFERENCES sponsorships (tenant_id, id),
  FOREIGN KEY (tenant_id, guest_identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX ix_guest_renewal_tokens_sponsorship ON guest_renewal_tokens (tenant_id, sponsorship_id, status);

CREATE TABLE guest_lifecycle_tasks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (kind IN ('sponsor_transfer','renewal_request','dual_status')),
  sponsorship_id TEXT NOT NULL,
  subject_identity_id BIGINT NOT NULL,
  trigger TEXT NOT NULL CHECK (trigger IN ('leaver','mover','ineligible','guest_request','conversion')),
  status TEXT NOT NULL CHECK (status IN ('open','done','declined','expired','cancelled')),
  deadline TEXT,
  outcome TEXT CHECK (outcome IN ('transferred','ended','suspended','renewed','dismissed','confirmed')),
  note TEXT,
  resolved_by TEXT,
  resolved_at TEXT,
  created_at TEXT NOT NULL,
  CHECK ((status = 'open') = (resolved_at IS NULL)),
  CHECK ((status = 'open') = (outcome IS NULL)),
  FOREIGN KEY (tenant_id, sponsorship_id) REFERENCES sponsorships (tenant_id, id),
  FOREIGN KEY (tenant_id, subject_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, resolved_by) REFERENCES platform_users (tenant_id, id)
);
CREATE UNIQUE INDEX ux_guest_lifecycle_tasks_open ON guest_lifecycle_tasks (tenant_id, sponsorship_id, kind) WHERE status = 'open';
CREATE INDEX ix_guest_lifecycle_tasks_status ON guest_lifecycle_tasks (tenant_id, status, deadline);

CREATE TABLE sponsorship_stepups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsorship_id TEXT NOT NULL,
  requested_ends_at TEXT NOT NULL,
  justification TEXT NOT NULL CHECK (justification <> ''),
  required_ial BIGINT NOT NULL CHECK (required_ial IN (1,2)),
  status TEXT NOT NULL CHECK (status IN ('pending','applied','cancelled')),
  requested_by TEXT,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  CHECK ((status = 'pending') = (resolved_at IS NULL)),
  FOREIGN KEY (tenant_id, sponsorship_id) REFERENCES sponsorships (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES platform_users (tenant_id, id)
);
CREATE UNIQUE INDEX ux_sponsorship_stepups_pending ON sponsorship_stepups (tenant_id, sponsorship_id) WHERE status = 'pending';

CREATE TABLE guest_deprovisioning (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  population TEXT NOT NULL CHECK (population IN ('visitor','contractor','volunteer','partner')),
  stage TEXT NOT NULL CHECK (stage IN ('grace','deprovisioned','purged','returned')),
  held_access BIGINT NOT NULL CHECK (held_access IN (0,1)),
  ended_at TEXT NOT NULL,
  grace_until TEXT NOT NULL,
  retention_until TEXT NOT NULL,
  deprovisioned_at TEXT,
  purged_at TEXT,
  returned_at TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, identity_id),
  CHECK ((stage = 'purged') = (purged_at IS NOT NULL)),
  CHECK ((stage = 'returned') = (returned_at IS NOT NULL)),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX ix_guest_deprovisioning_stage ON guest_deprovisioning (tenant_id, stage, grace_until);

-- Reminders are a ledger: never changed, never removed.

-- Reminders are a ledger: never changed, never removed.
CREATE TRIGGER guest_reminders_no_update BEFORE UPDATE ON guest_reminders
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('guest_reminders is append-only');
CREATE TRIGGER guest_reminders_no_delete BEFORE DELETE ON guest_reminders
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('guest_reminders is append-only');

-- A task's subject and sponsorship never change and a resolved task is final.
CREATE TRIGGER guest_lifecycle_tasks_immutable BEFORE UPDATE ON guest_lifecycle_tasks
	FOR EACH ROW WHEN (OLD.status <> 'open' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.kind <> OLD.kind
		OR NEW.sponsorship_id <> OLD.sponsorship_id OR NEW.subject_identity_id <> OLD.subject_identity_id
		OR NEW.trigger <> OLD.trigger OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('guest_lifecycle_tasks: resolved rows and identity columns are immutable');
CREATE TRIGGER guest_lifecycle_tasks_no_delete BEFORE DELETE ON guest_lifecycle_tasks
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('guest_lifecycle_tasks are append-only');

CREATE TRIGGER guest_renewal_tokens_immutable BEFORE UPDATE ON guest_renewal_tokens
	FOR EACH ROW WHEN (OLD.status <> 'issued' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsorship_id <> OLD.sponsorship_id
		OR NEW.guest_identity_id <> OLD.guest_identity_id OR NEW.token_hash <> OLD.token_hash OR NEW.expires_at <> OLD.expires_at
		OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('guest_renewal_tokens: spent rows and identity columns are immutable');
CREATE TRIGGER guest_renewal_tokens_no_delete BEFORE DELETE ON guest_renewal_tokens
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('guest_renewal_tokens are append-only');

CREATE TRIGGER sponsorship_stepups_immutable BEFORE UPDATE ON sponsorship_stepups
	FOR EACH ROW WHEN (OLD.status <> 'pending' OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsorship_id <> OLD.sponsorship_id
		OR NEW.requested_ends_at <> OLD.requested_ends_at OR NEW.justification <> OLD.justification
		OR NEW.required_ial <> OLD.required_ial OR NEW.created_at <> OLD.created_at)
	EXECUTE FUNCTION tessera_abort('sponsorship_stepups: resolved rows and identity columns are immutable');
CREATE TRIGGER sponsorship_stepups_no_delete BEFORE DELETE ON sponsorship_stepups
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('sponsorship_stepups are append-only');

-- A person's stage only moves forward, and a purge is final. A person who
-- returned starts a new cycle when their next affiliation ends: 'returned' goes
-- back to 'grace' with the new dates, and only that.
CREATE TRIGGER guest_deprovisioning_immutable BEFORE UPDATE ON guest_deprovisioning
	FOR EACH ROW WHEN (OLD.stage = 'purged' OR NEW.tenant_id <> OLD.tenant_id OR NEW.identity_id <> OLD.identity_id
		OR (OLD.stage = 'returned' AND NEW.stage <> 'grace')
		OR (OLD.stage <> 'returned' AND NEW.ended_at <> OLD.ended_at)
		OR (OLD.stage = 'deprovisioned' AND NEW.stage = 'grace'))
	EXECUTE FUNCTION tessera_abort('guest_deprovisioning: final rows and identity columns are immutable');
CREATE TRIGGER guest_deprovisioning_no_delete BEFORE DELETE ON guest_deprovisioning
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('guest_deprovisioning is append-only');
