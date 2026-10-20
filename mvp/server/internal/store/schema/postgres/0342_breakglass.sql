-- Postgres dialect of schema/0009_breakglass.sql (Phase 0 PR13, issue #17, kept in parity with the SQLite
-- file by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.
--
-- It also widens the admin_change_requests type CHECK to admit breakglass.register and
-- breakglass.revoke (SQLite changes the CHECK in 0008_admin_changes.sql and recreates an older table).

-- +goose Up

ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke'));

CREATE TABLE break_glass_credentials (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  change_request_id TEXT NOT NULL,
  credential_id BYTEA NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 1023),
  public_key BYTEA NOT NULL CHECK (length(public_key) > 0),
  sign_count BIGINT NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
  aaguid TEXT NOT NULL CHECK (length(aaguid) = 36),
  attestation_format TEXT NOT NULL CHECK (attestation_format <> 'none'),
  attestation_trust TEXT NOT NULL CHECK (attestation_trust IN ('basic','attca','mds_verified')),
  backup_eligible BIGINT NOT NULL CHECK (backup_eligible = 0),
  transports TEXT NOT NULL DEFAULT '[]' CHECK (transports IS JSON ARRAY),
  label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
  custodian TEXT NOT NULL CHECK (length(custodian) BETWEEN 1 AND 200),
  created_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, credential_id),
  UNIQUE (tenant_id, change_request_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, change_request_id) REFERENCES admin_change_requests (tenant_id, id)
);
CREATE INDEX break_glass_credentials_tenant ON break_glass_credentials(tenant_id, user_id);

CREATE TABLE break_glass_challenges (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  purpose TEXT NOT NULL CHECK (purpose IN ('registration','assertion')),
  challenge_hash TEXT NOT NULL CHECK (length(challenge_hash) = 64),
  session_data TEXT NOT NULL CHECK (session_data IS JSON),
  change_request_id TEXT,
  user_id TEXT,
  created_by_user_id TEXT,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, challenge_hash),
  CHECK (created_at < expires_at),
  CHECK ((purpose = 'registration') = (change_request_id IS NOT NULL AND user_id IS NOT NULL AND created_by_user_id IS NOT NULL)),
  FOREIGN KEY (tenant_id, change_request_id) REFERENCES admin_change_requests (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, created_by_user_id) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX break_glass_challenges_tenant ON break_glass_challenges(tenant_id, purpose, expires_at);

CREATE TABLE break_glass_uses (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  credential_row_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  used_at TEXT NOT NULL, ip TEXT, user_agent TEXT,
  answered_at TEXT, answered_by_user_id TEXT,
  reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 2000),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, session_id),
  CHECK ((answered_at IS NULL) = (answered_by_user_id IS NULL) AND (answered_at IS NULL) = (reason IS NULL)),
  FOREIGN KEY (tenant_id, credential_row_id) REFERENCES break_glass_credentials (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, session_id) REFERENCES sessions (tenant_id, id),
  FOREIGN KEY (tenant_id, answered_by_user_id) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX break_glass_uses_tenant ON break_glass_uses(tenant_id, used_at);
