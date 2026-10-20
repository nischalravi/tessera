-- Postgres dialect of schema/0255_mfa_posture.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE auth_methods (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  account_id BIGINT NOT NULL,
  external_id TEXT NOT NULL,
  system TEXT NOT NULL,
  strength TEXT NOT NULL CHECK (strength IN ('phishing_resistant','push_number_match','push','otp','sms_voice')),
  kind TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  enrolled_at TEXT,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, account_id, external_id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id)
);
CREATE INDEX ix_auth_methods_tenant_system ON auth_methods (tenant_id, system);

-- Whether the last sync of a system could read its methods. 'unavailable'
-- (a missing Graph scope, a refused Okta listing) means the methods stored for
-- the system are stale or absent and the report must say "unknown", never
-- "no MFA".
CREATE TABLE auth_method_sources (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','unavailable')),
  detail TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, system)
);

-- What an app or data platform reports about how an account signs in. Each
-- flag is NULL when the source does not provide it (unknown), 0 or 1 as
-- reported. Never inferred.
CREATE TABLE account_auth_signals (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  account_id BIGINT NOT NULL,
  has_local_password BIGINT CHECK (has_local_password IN (0,1)),
  mfa_enabled BIGINT CHECK (mfa_enabled IN (0,1)),
  sso_enforced BIGINT CHECK (sso_enforced IN (0,1)),
  observed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, account_id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id)
);

-- One row per day, dimension and group: how many identities have each best
-- method class. dimension 'all' has group_key 'all'; 'department' and
-- 'privileged_group' use the department or group name as group_key.
CREATE TABLE mfa_posture_snapshots (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  snapshot_date TEXT NOT NULL,
  dimension TEXT NOT NULL CHECK (dimension IN ('all','department','privileged_group')),
  group_key TEXT NOT NULL,
  total BIGINT NOT NULL,
  phishing_resistant BIGINT NOT NULL,
  push_number_match BIGINT NOT NULL,
  push BIGINT NOT NULL,
  otp BIGINT NOT NULL,
  sms_voice BIGINT NOT NULL,
  no_mfa BIGINT NOT NULL,
  unknown BIGINT NOT NULL,
  passkey_enrolled BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, snapshot_date, dimension, group_key)
);
