-- MFA posture (issue #109): registered authentication methods of IdP accounts,
-- how apps and data platforms sign their accounts in, and a daily coverage
-- snapshot.
--
-- Tenant-owned like every table of 0001_tenancy.sql: tenant_id references
-- tenants(id), every UNIQUE constraint starts with tenant_id, and the guard
-- triggers at the end refuse a reference to another tenant's account.
-- Nothing here holds a secret, a phone number or an e-mail address: a method
-- row is its class (phishing_resistant, ...), its kind (passkey, totp, ...)
-- and an optional device label such as "YubiKey 5C".

-- One row per registered method of an account. Replaced wholesale per system
-- by each sync that read the system's methods (ingest.AuthPosture).
CREATE TABLE IF NOT EXISTS auth_methods (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  external_id TEXT NOT NULL,
  system TEXT NOT NULL,
  strength TEXT NOT NULL CHECK (strength IN ('phishing_resistant','push_number_match','push','otp','sms_voice')),
  kind TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  enrolled_at TEXT,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, account_id, external_id)
);
CREATE INDEX IF NOT EXISTS ix_auth_methods_tenant_system ON auth_methods (tenant_id, system);

-- Whether the last sync of a system could read its methods. 'unavailable'
-- (a missing Graph scope, a refused Okta listing) means the methods stored for
-- the system are stale or absent and the report must say "unknown", never
-- "no MFA".
CREATE TABLE IF NOT EXISTS auth_method_sources (
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
CREATE TABLE IF NOT EXISTS account_auth_signals (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  has_local_password INTEGER CHECK (has_local_password IN (0,1)),
  mfa_enabled INTEGER CHECK (mfa_enabled IN (0,1)),
  sso_enforced INTEGER CHECK (sso_enforced IN (0,1)),
  observed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, account_id)
);

-- One row per day, dimension and group: how many identities have each best
-- method class. dimension 'all' has group_key 'all'; 'department' and
-- 'privileged_group' use the department or group name as group_key.
CREATE TABLE IF NOT EXISTS mfa_posture_snapshots (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  snapshot_date TEXT NOT NULL,
  dimension TEXT NOT NULL CHECK (dimension IN ('all','department','privileged_group')),
  group_key TEXT NOT NULL,
  total INTEGER NOT NULL,
  phishing_resistant INTEGER NOT NULL,
  push_number_match INTEGER NOT NULL,
  push INTEGER NOT NULL,
  otp INTEGER NOT NULL,
  sms_voice INTEGER NOT NULL,
  no_mfa INTEGER NOT NULL,
  unknown INTEGER NOT NULL,
  passkey_enrolled INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, snapshot_date, dimension, group_key)
);

CREATE TRIGGER IF NOT EXISTS tg_auth_methods_xtenant_ins BEFORE INSERT ON auth_methods
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: auth_methods'); END;

CREATE TRIGGER IF NOT EXISTS tg_auth_methods_xtenant_upd BEFORE UPDATE OF tenant_id, account_id ON auth_methods
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: auth_methods'); END;

CREATE TRIGGER IF NOT EXISTS tg_account_auth_signals_xtenant_ins BEFORE INSERT ON account_auth_signals
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: account_auth_signals'); END;

CREATE TRIGGER IF NOT EXISTS tg_account_auth_signals_xtenant_upd BEFORE UPDATE OF tenant_id, account_id ON account_auth_signals
WHEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: account_auth_signals'); END;
