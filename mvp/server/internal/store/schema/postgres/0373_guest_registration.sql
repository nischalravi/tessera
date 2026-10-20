-- Postgres dialect of schema/0373_guest_registration.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE guest_registrations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsor_identity_id BIGINT NOT NULL,
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
  decided_by TEXT,
  decided_at TEXT,
  identity_id BIGINT,
  intake_id TEXT,
  redact_after TEXT,
  redacted_at TEXT,
  created_at TEXT NOT NULL,
  CHECK (ends_at > starts_at),
  CHECK ((status = 'pending') = (decided_at IS NULL)),
  CHECK ((status = 'approved') = (identity_id IS NOT NULL)),
  CHECK (identity_id IS NULL OR intake_id IS NOT NULL),
  CHECK (redacted_at IS NOT NULL OR (given_name IS NOT NULL AND family_name IS NOT NULL AND email IS NOT NULL AND purpose IS NOT NULL)),
  CHECK (redacted_at IS NULL OR (given_name IS NULL AND family_name IS NULL AND email IS NULL AND purpose IS NULL)),
  FOREIGN KEY (tenant_id, sponsor_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, intake_id) REFERENCES intake_records (tenant_id, id)
);
CREATE UNIQUE INDEX ux_guest_registrations_pending ON guest_registrations (tenant_id, sponsor_identity_id, email_hmac) WHERE status = 'pending';
CREATE INDEX ix_guest_registrations_sponsor ON guest_registrations (tenant_id, sponsor_identity_id, status, created_at);
CREATE INDEX ix_guest_registrations_due ON guest_registrations (tenant_id, status, expires_at);

CREATE TABLE guest_sponsor_codes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sponsor_identity_id BIGINT NOT NULL,
  code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  UNIQUE (tenant_id, code_hash),
  FOREIGN KEY (tenant_id, sponsor_identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX ix_guest_sponsor_codes_sponsor ON guest_sponsor_codes (tenant_id, sponsor_identity_id, status);

-- A request's who, what and when never change; a decided request keeps its
-- decision; once reduced, the personal data cannot come back.

CREATE TRIGGER guest_registrations_immutable BEFORE UPDATE ON guest_registrations
	FOR EACH ROW WHEN (NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsor_identity_id <> OLD.sponsor_identity_id
		OR NEW.via <> OLD.via OR NEW.email_hmac <> OLD.email_hmac OR NEW.starts_at <> OLD.starts_at OR NEW.ends_at <> OLD.ends_at
		OR NEW.expires_at <> OLD.expires_at OR NEW.created_at <> OLD.created_at
		OR (OLD.status <> 'pending' AND (NEW.status <> OLD.status OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
			OR NEW.decided_by IS DISTINCT FROM OLD.decided_by OR NEW.identity_id IS DISTINCT FROM OLD.identity_id OR NEW.intake_id IS DISTINCT FROM OLD.intake_id))
		OR (OLD.redacted_at IS NOT NULL AND NEW.redacted_at IS DISTINCT FROM OLD.redacted_at))
	EXECUTE FUNCTION tessera_abort('guest_registrations: identity columns and decisions are immutable');
CREATE TRIGGER guest_registrations_no_delete BEFORE DELETE ON guest_registrations
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('guest_registrations are append-only');

CREATE TRIGGER guest_sponsor_codes_immutable BEFORE UPDATE ON guest_sponsor_codes
	FOR EACH ROW WHEN (NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.sponsor_identity_id <> OLD.sponsor_identity_id
		OR NEW.code_hash <> OLD.code_hash OR NEW.expires_at <> OLD.expires_at OR NEW.created_at <> OLD.created_at
		OR OLD.status <> 'active')
	EXECUTE FUNCTION tessera_abort('guest_sponsor_codes: revoked rows and identity columns are immutable');
CREATE TRIGGER guest_sponsor_codes_no_delete BEFORE DELETE ON guest_sponsor_codes
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('guest_sponsor_codes are append-only');
