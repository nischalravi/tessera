-- Postgres dialect of schema/0005_auth.sql (Phase 0 PR14). See 0001_tenancy.sql.
-- References between tenant tables are composite (tenant_id, x_id) foreign
-- keys, so no guard triggers are needed here. The sessions and authn_contexts
-- pair is one composite key over (tenant_id, user_id, id): a session's
-- authentication context always belongs to the session's user.

-- +goose Up

CREATE TABLE idp_connections (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('oidc','saml','oauth2')),
  profile TEXT NOT NULL CHECK (profile IN ('okta','entra','google','generic_oidc','generic_saml','github','generic_oauth2','dev_mock')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
  is_default BIGINT NOT NULL DEFAULT 0,
  verified_domains TEXT NOT NULL DEFAULT '[]',
  issuer TEXT, discovery_url TEXT, client_id TEXT, client_auth_method TEXT,
  client_secret_enc BYTEA, client_signing_kid TEXT,
  scopes TEXT NOT NULL DEFAULT '["openid","email","profile"]',
  id_token_algs TEXT NOT NULL DEFAULT '["RS256","ES256","PS256"]',
  step_up_request TEXT NOT NULL DEFAULT '{}',
  discovery_cache TEXT, jwks_cache TEXT, jwks_cached_at TEXT,
  idp_entity_id TEXT, idp_sso_url TEXT,
  authorization_endpoint TEXT, token_endpoint TEXT, userinfo_endpoint TEXT,
  idp_signing_certs TEXT NOT NULL DEFAULT '[]',
  metadata_url TEXT,
  pin_certs BIGINT NOT NULL DEFAULT 1,
  sp_key_enc BYTEA, sp_cert_pem TEXT,
  subject_source TEXT NOT NULL DEFAULT 'nameid_persistent',
  attribute_map TEXT NOT NULL DEFAULT '{}',
  authn_mapping TEXT NOT NULL DEFAULT '{}',
  assume_phishing_resistant BIGINT NOT NULL DEFAULT 0,
  groups_claim TEXT,
  group_role_mapping TEXT NOT NULL DEFAULT '{}',
  jit_provisioning BIGINT NOT NULL DEFAULT 1,
  default_role TEXT NOT NULL DEFAULT 'viewer' CHECK (default_role IN ('viewer','operator','auditor')),
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  last_change_request_id TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name)
);
CREATE INDEX idp_connections_tenant ON idp_connections(tenant_id);

CREATE TABLE platform_users (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  email TEXT, display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  is_break_glass BIGINT NOT NULL DEFAULT 0,
  identity_id BIGINT,
  created_at TEXT NOT NULL, last_login_at TEXT, disabled_at TEXT, disabled_reason TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);
CREATE INDEX platform_users_tenant ON platform_users(tenant_id);

CREATE TABLE external_logins (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  idp_connection_id TEXT NOT NULL,
  issuer TEXT NOT NULL, subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  email_at_last_login TEXT, created_at TEXT NOT NULL, last_seen_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, idp_connection_id, subject),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, idp_connection_id) REFERENCES idp_connections (tenant_id, id)
);
CREATE INDEX external_logins_user ON external_logins(tenant_id, user_id);

CREATE TABLE role_assignments (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer','operator','auditor','policy_admin','tenant_admin','break_glass')),
  source TEXT NOT NULL CHECK (source IN ('manual','idp_group','bootstrap','break_glass')),
  granted_by_user_id TEXT, change_request_id TEXT,
  created_at TEXT NOT NULL, expires_at TEXT,
  UNIQUE (tenant_id, user_id, role, source),
  CHECK (NOT (source = 'idp_group' AND role IN ('policy_admin','tenant_admin','break_glass'))),
  CHECK (role NOT IN ('policy_admin','tenant_admin','break_glass') OR source = 'bootstrap' OR change_request_id IS NOT NULL),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, granted_by_user_id) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX role_assignments_user ON role_assignments(tenant_id, user_id);

CREATE TABLE authn_contexts (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  idp_connection_id TEXT,
  protocol TEXT NOT NULL CHECK (protocol IN ('oidc','saml','oauth2','webauthn')),
  purpose TEXT NOT NULL CHECK (purpose IN ('login','step_up','device_approval','break_glass','bootstrap')),
  acr TEXT, amr TEXT NOT NULL DEFAULT '[]', methods TEXT NOT NULL DEFAULT '[]',
  aal BIGINT NOT NULL CHECK (aal BETWEEN 0 AND 3),
  phishing_resistant BIGINT NOT NULL CHECK (phishing_resistant IN (0, 1)),
  phr_basis TEXT NOT NULL CHECK (phr_basis IN ('acr','amr','connection_attestation','webauthn_attested','none')),
  tessera_acr TEXT NOT NULL CHECK (tessera_acr IN ('urn:tessera:acr:aal1','urn:tessera:acr:aal2','urn:tessera:acr:phr','urn:tessera:acr:phrh')),
  auth_time TEXT NOT NULL, idp_session_id TEXT,
  device TEXT, risk TEXT, ip TEXT, user_agent TEXT,
  mapping_profile TEXT NOT NULL, mapping_version BIGINT NOT NULL,
  claims_sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
  CHECK ((phishing_resistant = 1) = (phr_basis <> 'none')),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, user_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, idp_connection_id) REFERENCES idp_connections (tenant_id, id)
);
CREATE INDEX authn_contexts_user ON authn_contexts(tenant_id, user_id);
CREATE TRIGGER authn_contexts_immutable BEFORE UPDATE ON authn_contexts
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('authn_contexts is immutable');
CREATE TRIGGER authn_contexts_no_delete BEFORE DELETE ON authn_contexts
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('authn_contexts is immutable');

CREATE TABLE sessions (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('browser','cli','break_glass')),
  secret_hash TEXT UNIQUE CHECK (secret_hash IS NULL OR length(secret_hash) = 64),
  csrf_secret TEXT,
  initial_authn_context_id TEXT NOT NULL,
  current_authn_context_id TEXT NOT NULL,
  client_id TEXT,
  created_at TEXT NOT NULL, last_activity_at TEXT NOT NULL,
  idle_expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','expired')),
  revoked_at TEXT, revoked_reason TEXT, ip_first TEXT, user_agent_first TEXT,
  CHECK (kind <> 'browser' OR (secret_hash IS NOT NULL AND csrf_secret IS NOT NULL)),
  CHECK (idle_expires_at <= absolute_expires_at),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id, initial_authn_context_id) REFERENCES authn_contexts (tenant_id, user_id, id),
  FOREIGN KEY (tenant_id, user_id, current_authn_context_id) REFERENCES authn_contexts (tenant_id, user_id, id)
);
CREATE INDEX sessions_tenant_user ON sessions(tenant_id, user_id);

CREATE TABLE login_transactions (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  cookie_hash TEXT NOT NULL UNIQUE CHECK (length(cookie_hash) = 64),
  idp_connection_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('login','step_up','device_approval','bootstrap')),
  state_hash TEXT, nonce TEXT, pkce_verifier_enc BYTEA, saml_request_id TEXT,
  required_tessera_acr TEXT, max_age BIGINT,
  session_id TEXT, expected_external_login_id TEXT, device_grant_id TEXT, bootstrap_invitation_id TEXT,
  return_to TEXT NOT NULL DEFAULT '/',
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT,
  -- a same-site path: starts with one '/', no backslash, no control characters
  CHECK (substr(return_to, 1, 1) = '/' AND substr(return_to, 1, 2) <> '//' AND length(return_to) <= 2048
    AND strpos(return_to, chr(92)) = 0
    AND return_to !~ '[[:cntrl:]]'),
  FOREIGN KEY (tenant_id, idp_connection_id) REFERENCES idp_connections (tenant_id, id),
  FOREIGN KEY (tenant_id, session_id) REFERENCES sessions (tenant_id, id),
  FOREIGN KEY (tenant_id, expected_external_login_id) REFERENCES external_logins (tenant_id, id)
);
CREATE INDEX login_transactions_tenant ON login_transactions(tenant_id);

-- The *_by_user_id columns of the workflow tables (§7.3) name platform users
-- of the same tenant.
ALTER TABLE access_requests ADD FOREIGN KEY (tenant_id, requested_by_user_id) REFERENCES platform_users (tenant_id, id);
ALTER TABLE access_requests ADD FOREIGN KEY (tenant_id, decided_by_user_id) REFERENCES platform_users (tenant_id, id);
ALTER TABLE review_items ADD FOREIGN KEY (tenant_id, decided_by_user_id) REFERENCES platform_users (tenant_id, id);
ALTER TABLE hris_events ADD FOREIGN KEY (tenant_id, executed_by_user_id) REFERENCES platform_users (tenant_id, id);
