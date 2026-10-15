-- Phase 0 PR5: the auth core (design §7.4, §7.5, §11, §12).
--
-- Every table is tenant-owned: tenant_id references tenants(id), every UNIQUE
-- constraint starts with tenant_id (except the two globally unique bearer
-- hashes, sessions.secret_hash and login_transactions.cookie_hash, which are
-- the only lookups that run before the tenant is known, §14.2), and the guard
-- triggers at the end refuse a reference to another tenant's row. UUID text
-- primary keys; RFC 3339 UTC timestamps with microseconds (store.RT).
--
-- Bearer secrets are stored only as SHA-256 hex: the session cookie
-- (secret_hash) and the login-transaction cookie (cookie_hash).

CREATE TABLE IF NOT EXISTS idp_connections (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('oidc','saml','oauth2')),
  profile TEXT NOT NULL CHECK (profile IN ('okta','entra','google','generic_oidc','generic_saml','github','generic_oauth2','dev_mock')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
  is_default INTEGER NOT NULL DEFAULT 0,
  verified_domains TEXT NOT NULL DEFAULT '[]',
  issuer TEXT, discovery_url TEXT, client_id TEXT, client_auth_method TEXT,
  client_secret_enc BLOB, client_signing_kid TEXT,
  scopes TEXT NOT NULL DEFAULT '["openid","email","profile"]',
  id_token_algs TEXT NOT NULL DEFAULT '["RS256","ES256","PS256"]',
  step_up_request TEXT NOT NULL DEFAULT '{}',
  discovery_cache TEXT, jwks_cache TEXT, jwks_cached_at TEXT,
  idp_entity_id TEXT, idp_sso_url TEXT,
  -- OAuth 2.0-only providers (no ID token): pinned endpoints, never discovered
  authorization_endpoint TEXT, token_endpoint TEXT, userinfo_endpoint TEXT,
  idp_signing_certs TEXT NOT NULL DEFAULT '[]',
  metadata_url TEXT,
  pin_certs INTEGER NOT NULL DEFAULT 1,
  sp_key_enc BLOB, sp_cert_pem TEXT,
  subject_source TEXT NOT NULL DEFAULT 'nameid_persistent',
  attribute_map TEXT NOT NULL DEFAULT '{}',
  authn_mapping TEXT NOT NULL DEFAULT '{}',
  assume_phishing_resistant INTEGER NOT NULL DEFAULT 0,
  groups_claim TEXT,
  group_role_mapping TEXT NOT NULL DEFAULT '{}',
  jit_provisioning INTEGER NOT NULL DEFAULT 1,
  default_role TEXT NOT NULL DEFAULT 'viewer' CHECK (default_role IN ('viewer','operator','auditor')),
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  last_change_request_id TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idp_connections_tenant ON idp_connections(tenant_id);

-- PlatformUser: a person who signs in to Tessera (not a governed Identity).
CREATE TABLE IF NOT EXISTS platform_users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  email TEXT, display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  is_break_glass INTEGER NOT NULL DEFAULT 0,
  identity_id INTEGER REFERENCES identities (id),
  created_at TEXT NOT NULL, last_login_at TEXT, disabled_at TEXT, disabled_reason TEXT,
  UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS platform_users_tenant ON platform_users(tenant_id);

-- ExternalLogin: the immutable (connection, subject) -> user link. Never email.
CREATE TABLE IF NOT EXISTS external_logins (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  idp_connection_id TEXT NOT NULL REFERENCES idp_connections (id),
  issuer TEXT NOT NULL, subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  email_at_last_login TEXT, created_at TEXT NOT NULL, last_seen_at TEXT,
  UNIQUE (tenant_id, idp_connection_id, subject)
);
CREATE INDEX IF NOT EXISTS external_logins_user ON external_logins(tenant_id, user_id);

CREATE TABLE IF NOT EXISTS role_assignments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  role TEXT NOT NULL CHECK (role IN ('viewer','operator','auditor','policy_admin','tenant_admin','break_glass')),
  source TEXT NOT NULL CHECK (source IN ('manual','idp_group','bootstrap','break_glass')),
  granted_by_user_id TEXT, change_request_id TEXT,
  created_at TEXT NOT NULL, expires_at TEXT,
  UNIQUE (tenant_id, user_id, role, source),
  -- E1: IdP groups never confer admin roles; admin roles need a change request or bootstrap
  CHECK (NOT (source = 'idp_group' AND role IN ('policy_admin','tenant_admin','break_glass'))),
  -- admin roles and break-glass enrolment need a two-person change request (§15)
  CHECK (role NOT IN ('policy_admin','tenant_admin','break_glass') OR source = 'bootstrap' OR change_request_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS role_assignments_user ON role_assignments(tenant_id, user_id);

-- AuthnContextRecord: one per successful authentication or step-up. Immutable.
CREATE TABLE IF NOT EXISTS authn_contexts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  idp_connection_id TEXT REFERENCES idp_connections (id),
  protocol TEXT NOT NULL CHECK (protocol IN ('oidc','saml','oauth2','webauthn')),
  purpose TEXT NOT NULL CHECK (purpose IN ('login','step_up','device_approval','break_glass','bootstrap')),
  acr TEXT, amr TEXT NOT NULL DEFAULT '[]', methods TEXT NOT NULL DEFAULT '[]',
  aal INTEGER NOT NULL CHECK (aal BETWEEN 0 AND 3),
  phishing_resistant INTEGER NOT NULL CHECK (phishing_resistant IN (0, 1)),
  phr_basis TEXT NOT NULL CHECK (phr_basis IN ('acr','amr','connection_attestation','webauthn_attested','none')),
  tessera_acr TEXT NOT NULL CHECK (tessera_acr IN ('urn:tessera:acr:aal1','urn:tessera:acr:aal2','urn:tessera:acr:phr','urn:tessera:acr:phrh')),
  auth_time TEXT NOT NULL, idp_session_id TEXT,
  device TEXT, risk TEXT, ip TEXT, user_agent TEXT,
  mapping_profile TEXT NOT NULL, mapping_version INTEGER NOT NULL,
  claims_sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
  -- phishing resistance always names its basis, and "none" never claims it
  CHECK ((phishing_resistant = 1) = (phr_basis <> 'none'))
);
CREATE INDEX IF NOT EXISTS authn_contexts_user ON authn_contexts(tenant_id, user_id);
CREATE TRIGGER IF NOT EXISTS authn_contexts_immutable BEFORE UPDATE ON authn_contexts
BEGIN SELECT RAISE(ABORT, 'authn_contexts is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authn_contexts_no_delete BEFORE DELETE ON authn_contexts
BEGIN SELECT RAISE(ABORT, 'authn_contexts is immutable'); END;

-- Session: browser (cookie) and, from PR10, CLI sessions. Only the SHA-256 of
-- the cookie secret is stored; the same row keeps its id across rotations.
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  kind TEXT NOT NULL CHECK (kind IN ('browser','cli','break_glass')),
  secret_hash TEXT UNIQUE CHECK (secret_hash IS NULL OR length(secret_hash) = 64),
  csrf_secret TEXT,
  initial_authn_context_id TEXT NOT NULL REFERENCES authn_contexts (id),
  current_authn_context_id TEXT NOT NULL REFERENCES authn_contexts (id),
  client_id TEXT,
  created_at TEXT NOT NULL, last_activity_at TEXT NOT NULL,
  idle_expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','expired')),
  revoked_at TEXT, revoked_reason TEXT, ip_first TEXT, user_agent_first TEXT,
  CHECK (kind <> 'browser' OR (secret_hash IS NOT NULL AND csrf_secret IS NOT NULL)),
  CHECK (idle_expires_at <= absolute_expires_at)
);
CREATE INDEX IF NOT EXISTS sessions_tenant_user ON sessions(tenant_id, user_id);

-- LoginTransaction: pre-auth state of one OIDC/SAML round trip (PR6, PR9),
-- bound to the __Host-tessera_login cookie.
CREATE TABLE IF NOT EXISTS login_transactions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  cookie_hash TEXT NOT NULL UNIQUE CHECK (length(cookie_hash) = 64),
  idp_connection_id TEXT NOT NULL REFERENCES idp_connections (id),
  purpose TEXT NOT NULL CHECK (purpose IN ('login','step_up','device_approval','bootstrap','claim')),
  state_hash TEXT, nonce TEXT, pkce_verifier_enc BLOB, saml_request_id TEXT,
  required_tessera_acr TEXT, max_age INTEGER,
  session_id TEXT, expected_external_login_id TEXT, device_grant_id TEXT, bootstrap_invitation_id TEXT,
  return_to TEXT NOT NULL DEFAULT '/',
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT,
  -- a same-site path: starts with one '/', no backslash (browsers read '/\x'
  -- as '//x'), no control characters; store.ValidReturnTo checks the same in Go
  CHECK (substr(return_to, 1, 1) = '/' AND substr(return_to, 1, 2) <> '//' AND length(return_to) <= 2048
    AND instr(return_to, char(92)) = 0
    AND NOT (return_to GLOB ('*[' || char(1) || '-' || char(31) || char(127) || ']*')))
);
CREATE INDEX IF NOT EXISTS login_transactions_tenant ON login_transactions(tenant_id);

-- ---------------------------------------------------------------- guard triggers
-- Refuse a reference to another tenant's row (the SQLite counterpart of the
-- composite foreign keys Postgres gets in PR14).

CREATE TRIGGER IF NOT EXISTS tg_platform_users_xtenant_ins BEFORE INSERT ON platform_users
WHEN (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: platform_users'); END;

CREATE TRIGGER IF NOT EXISTS tg_platform_users_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON platform_users
WHEN (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: platform_users'); END;

CREATE TRIGGER IF NOT EXISTS tg_external_logins_xtenant_ins BEFORE INSERT ON external_logins
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM idp_connections p WHERE p.id = NEW.idp_connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: external_logins'); END;

CREATE TRIGGER IF NOT EXISTS tg_external_logins_xtenant_upd BEFORE UPDATE OF tenant_id, user_id, idp_connection_id ON external_logins
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM idp_connections p WHERE p.id = NEW.idp_connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: external_logins'); END;

CREATE TRIGGER IF NOT EXISTS tg_role_assignments_xtenant_ins BEFORE INSERT ON role_assignments
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.granted_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.granted_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: role_assignments'); END;

CREATE TRIGGER IF NOT EXISTS tg_role_assignments_xtenant_upd BEFORE UPDATE OF tenant_id, user_id, granted_by_user_id ON role_assignments
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.granted_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.granted_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: role_assignments'); END;

CREATE TRIGGER IF NOT EXISTS tg_authn_contexts_xtenant_ins BEFORE INSERT ON authn_contexts
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.idp_connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM idp_connections p WHERE p.id = NEW.idp_connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: authn_contexts'); END;

CREATE TRIGGER IF NOT EXISTS tg_sessions_xtenant_ins BEFORE INSERT ON sessions
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM authn_contexts p WHERE p.id = NEW.initial_authn_context_id AND (p.tenant_id <> NEW.tenant_id OR p.user_id <> NEW.user_id))
	OR EXISTS (SELECT 1 FROM authn_contexts p WHERE p.id = NEW.current_authn_context_id AND (p.tenant_id <> NEW.tenant_id OR p.user_id <> NEW.user_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sessions'); END;

-- the authentication context of a session always belongs to its user
CREATE TRIGGER IF NOT EXISTS tg_sessions_xtenant_upd BEFORE UPDATE OF tenant_id, user_id, initial_authn_context_id, current_authn_context_id ON sessions
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM authn_contexts p WHERE p.id = NEW.initial_authn_context_id AND (p.tenant_id <> NEW.tenant_id OR p.user_id <> NEW.user_id))
	OR EXISTS (SELECT 1 FROM authn_contexts p WHERE p.id = NEW.current_authn_context_id AND (p.tenant_id <> NEW.tenant_id OR p.user_id <> NEW.user_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sessions'); END;

CREATE TRIGGER IF NOT EXISTS tg_login_transactions_xtenant_ins BEFORE INSERT ON login_transactions
WHEN EXISTS (SELECT 1 FROM idp_connections p WHERE p.id = NEW.idp_connection_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.session_id IS NOT NULL AND EXISTS (SELECT 1 FROM sessions p WHERE p.id = NEW.session_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.expected_external_login_id IS NOT NULL AND EXISTS (SELECT 1 FROM external_logins p WHERE p.id = NEW.expected_external_login_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: login_transactions'); END;

CREATE TRIGGER IF NOT EXISTS tg_login_transactions_xtenant_upd BEFORE UPDATE OF tenant_id, idp_connection_id, session_id, expected_external_login_id ON login_transactions
WHEN EXISTS (SELECT 1 FROM idp_connections p WHERE p.id = NEW.idp_connection_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.session_id IS NOT NULL AND EXISTS (SELECT 1 FROM sessions p WHERE p.id = NEW.session_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.expected_external_login_id IS NOT NULL AND EXISTS (SELECT 1 FROM external_logins p WHERE p.id = NEW.expected_external_login_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: login_transactions'); END;

-- The *_by_user_id columns of the workflow tables (§7.3) name platform users
-- of the same tenant.
CREATE TRIGGER IF NOT EXISTS tg_access_requests_users_xtenant BEFORE UPDATE OF requested_by_user_id, decided_by_user_id ON access_requests
WHEN (NEW.requested_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_requests_users_xtenant_ins BEFORE INSERT ON access_requests
WHEN (NEW.requested_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_items_users_xtenant BEFORE UPDATE OF decided_by_user_id ON review_items
WHEN NEW.decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by_user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_hris_events_users_xtenant BEFORE UPDATE OF executed_by_user_id ON hris_events
WHEN NEW.executed_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.executed_by_user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: hris_events'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_items_users_xtenant_ins BEFORE INSERT ON review_items
WHEN NEW.decided_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by_user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_hris_events_users_xtenant_ins BEFORE INSERT ON hris_events
WHEN NEW.executed_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.executed_by_user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: hris_events'); END;
