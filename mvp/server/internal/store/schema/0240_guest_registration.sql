-- Guest self-registration with sponsor approval (guest accounts design §3,
-- §6.4, T16, issue #66 / GU-3).
--
-- guest_registrations: what a visitor typed on the public page. It is a request,
-- not a person: nothing is created in identities, accounts or claim tokens until
-- the named sponsor approves (the identity and the claim link then come from the
-- ordinary invitation path, and identity_id / intake_id point at them). A
-- registration is pending until the sponsor decides or expires_at passes. The
-- name, address and purpose are PII: they are reduced to NULL when the request is
-- approved (the person record holds them from then on) and redact_after after it
-- was denied or expired; the row stays as a tombstone (id, sponsor, status,
-- dates, the address's keyed hash). One pending request per sponsor and address.
--
-- guest_sponsor_codes: the short code a sponsor shares so a visitor can name
-- them without searching. Only a keyed hash of the code is stored. A sponsor has
-- one active code; a new one revokes the old.
--
-- Tenant-owned like 0001_tenancy.sql: every UNIQUE starts with tenant_id and
-- guard triggers refuse a reference to another tenant's row. Created with IF
-- NOT EXISTS; a reseed drops and recreates (store.tables).

CREATE TABLE IF NOT EXISTS guest_registrations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsor_identity_id INTEGER NOT NULL REFERENCES identities (id),
  via TEXT NOT NULL CHECK (via IN ('search','code')),
  given_name TEXT,
  family_name TEXT,
  email TEXT,
  purpose TEXT,
  email_hmac TEXT NOT NULL CHECK (email_hmac <> ''),
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired')),
  expires_at TEXT NOT NULL,
  decided_by TEXT REFERENCES platform_users (id),
  decided_at TEXT,
  identity_id INTEGER REFERENCES identities (id),
  intake_id TEXT REFERENCES intake_records (id),
  redact_after TEXT,
  redacted_at TEXT,
  created_at TEXT NOT NULL,
  CHECK (ends_at > starts_at),
  CHECK ((status = 'pending') = (decided_at IS NULL)),
  CHECK ((status = 'approved') = (identity_id IS NOT NULL)),
  CHECK (identity_id IS NULL OR intake_id IS NOT NULL),
  CHECK (redacted_at IS NOT NULL OR (given_name IS NOT NULL AND family_name IS NOT NULL AND email IS NOT NULL AND purpose IS NOT NULL)),
  CHECK (redacted_at IS NULL OR (given_name IS NULL AND family_name IS NULL AND email IS NULL AND purpose IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_guest_registrations_pending ON guest_registrations (tenant_id, sponsor_identity_id, email_hmac) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS ix_guest_registrations_sponsor ON guest_registrations (tenant_id, sponsor_identity_id, status, created_at);
CREATE INDEX IF NOT EXISTS ix_guest_registrations_due ON guest_registrations (tenant_id, status, expires_at);

CREATE TABLE IF NOT EXISTS guest_sponsor_codes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsor_identity_id INTEGER NOT NULL REFERENCES identities (id),
  code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  UNIQUE (tenant_id, code_hash)
);
CREATE INDEX IF NOT EXISTS ix_guest_sponsor_codes_sponsor ON guest_sponsor_codes (tenant_id, sponsor_identity_id, status);

-- A request's who, what and when never change; a decided request keeps its
-- decision; once reduced, the personal data cannot come back.
CREATE TRIGGER IF NOT EXISTS tg_guest_registrations_immutable BEFORE UPDATE ON guest_registrations
WHEN NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsor_identity_id <> OLD.sponsor_identity_id
	OR NEW.via <> OLD.via OR NEW.email_hmac <> OLD.email_hmac OR NEW.starts_at <> OLD.starts_at OR NEW.ends_at <> OLD.ends_at
	OR NEW.expires_at <> OLD.expires_at OR NEW.created_at <> OLD.created_at
	OR (OLD.status <> 'pending' AND (NEW.status <> OLD.status OR NEW.decided_at IS NOT OLD.decided_at
		OR NEW.decided_by IS NOT OLD.decided_by OR NEW.identity_id IS NOT OLD.identity_id OR NEW.intake_id IS NOT OLD.intake_id))
	OR (OLD.redacted_at IS NOT NULL AND NEW.redacted_at IS NOT OLD.redacted_at)
BEGIN SELECT RAISE(ABORT, 'guest_registrations: identity columns and decisions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_registrations_no_delete BEFORE DELETE ON guest_registrations
BEGIN SELECT RAISE(ABORT, 'guest_registrations are append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_guest_sponsor_codes_immutable BEFORE UPDATE ON guest_sponsor_codes
WHEN NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsor_identity_id <> OLD.sponsor_identity_id
	OR NEW.code_hash <> OLD.code_hash OR NEW.expires_at <> OLD.expires_at OR NEW.created_at <> OLD.created_at
	OR OLD.status <> 'active'
BEGIN SELECT RAISE(ABORT, 'guest_sponsor_codes: revoked rows and identity columns are immutable'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_sponsor_codes_no_delete BEFORE DELETE ON guest_sponsor_codes
BEGIN SELECT RAISE(ABORT, 'guest_sponsor_codes are append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_guest_registrations_xtenant_ins BEFORE INSERT ON guest_registrations
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.intake_id IS NOT NULL AND EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_registrations'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_registrations_xtenant_upd BEFORE UPDATE OF tenant_id, sponsor_identity_id, identity_id, intake_id, decided_by ON guest_registrations
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.intake_id IS NOT NULL AND EXISTS (SELECT 1 FROM intake_records p WHERE p.id = NEW.intake_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_registrations'); END;

CREATE TRIGGER IF NOT EXISTS tg_guest_sponsor_codes_xtenant_ins BEFORE INSERT ON guest_sponsor_codes
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_sponsor_codes'); END;
CREATE TRIGGER IF NOT EXISTS tg_guest_sponsor_codes_xtenant_upd BEFORE UPDATE OF tenant_id, sponsor_identity_id ON guest_sponsor_codes
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: guest_sponsor_codes'); END;
