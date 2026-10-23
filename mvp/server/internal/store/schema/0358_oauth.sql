-- Phase 0 PR10: the OAuth authorization server (design §7.4, §7.5, §9.3, §10).
--
-- api_clients: the OAuth clients of a tenant. The first-party CLI client
-- ("tessera-cli", kind first_party_cli) is created per tenant by
-- oauth.EnsureCLIClient; machine clients arrive with PR11.
-- device_grants: RFC 8628 device authorizations (hash-only device and user
-- codes, 300 s).
-- refresh_tokens: DPoP-bound, rotating refresh tokens with a family id for
-- reuse detection (hash-only).
--
-- All three are tenant-owned: every UNIQUE constraint starts with tenant_id
-- (the OAuth endpoints live under /t/{slug}, so the tenant is known before any
-- lookup), and the guard triggers at the end refuse a reference to another
-- tenant's row. replay_cache (0007_replay.sql) holds the DPoP proof jti values
-- (kind dpop_jti). Timestamps are RFC 3339 UTC with microseconds (store.RT).

CREATE TABLE IF NOT EXISTS api_clients (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 3 AND 64),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('first_party_cli','machine')),
  grant_types TEXT NOT NULL DEFAULT '[]',
  token_endpoint_auth_method TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('none','private_key_jwt')),
  jwks TEXT,
  dpop_required INTEGER NOT NULL DEFAULT 1 CHECK (dpop_required IN (0, 1)),
  allowed_scopes TEXT NOT NULL DEFAULT '[]',
  roles TEXT NOT NULL DEFAULT '[]',
  owner_user_id TEXT REFERENCES platform_users (id),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at TEXT NOT NULL, last_used_at TEXT, change_request_id TEXT,
  -- who vouched for the client's permissions (issue #522, see store.APIClient.ApprovedBy); added to an existing database by DB.upgradeSecurityControls
  approved_by TEXT NOT NULL DEFAULT '',
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, client_id),
  -- every machine client has an owner (the NHI owner rule)
  CHECK (kind <> 'machine' OR owner_user_id IS NOT NULL),
  -- the CLI is a public client and always uses DPoP
  CHECK (kind <> 'first_party_cli' OR (token_endpoint_auth_method = 'none' AND dpop_required = 1))
);
CREATE INDEX IF NOT EXISTS api_clients_tenant ON api_clients(tenant_id);

CREATE TABLE IF NOT EXISTS device_grants (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  client_id TEXT NOT NULL,
  device_code_hash TEXT NOT NULL CHECK (length(device_code_hash) = 64),
  user_code_hash TEXT NOT NULL CHECK (length(user_code_hash) = 64),
  scope TEXT NOT NULL,
  required_tessera_acr TEXT, max_age INTEGER,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired','consumed')),
  request_ip TEXT, request_user_agent TEXT,
  poll_interval INTEGER NOT NULL DEFAULT 5, last_polled_at TEXT,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  approved_by_user_id TEXT REFERENCES platform_users (id),
  approved_authn_context_id TEXT REFERENCES authn_contexts (id),
  approved_at TEXT,
  session_id TEXT REFERENCES sessions (id),
  lookup_failures INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, device_code_hash)
);
CREATE INDEX IF NOT EXISTS device_grants_user_code ON device_grants(tenant_id, user_code_hash);
-- a user code is unique among the pending grants of a tenant
CREATE UNIQUE INDEX IF NOT EXISTS device_grants_pending_user_code ON device_grants(tenant_id, user_code_hash) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
  family_id TEXT NOT NULL, parent_id TEXT,
  session_id TEXT NOT NULL REFERENCES sessions (id),
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  client_id TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt) BETWEEN 20 AND 64),
  scope TEXT NOT NULL,
  issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL,
  used_at TEXT, revoked_at TEXT, revoked_reason TEXT,
  UNIQUE (tenant_id, token_hash),
  CHECK (expires_at <= absolute_expires_at)
);
CREATE INDEX IF NOT EXISTS refresh_tokens_family ON refresh_tokens(tenant_id, family_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_session ON refresh_tokens(tenant_id, session_id);

-- ---------------------------------------------------------------- guard triggers

CREATE TRIGGER IF NOT EXISTS tg_api_clients_xtenant_ins BEFORE INSERT ON api_clients
WHEN NEW.owner_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.owner_user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: api_clients'); END;

CREATE TRIGGER IF NOT EXISTS tg_api_clients_xtenant_upd BEFORE UPDATE OF tenant_id, owner_user_id ON api_clients
WHEN NEW.owner_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.owner_user_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: api_clients'); END;

-- client_id names a client of the same tenant (a dangling name is refused too)
CREATE TRIGGER IF NOT EXISTS tg_device_grants_xtenant_ins BEFORE INSERT ON device_grants
WHEN NOT EXISTS (SELECT 1 FROM api_clients p WHERE p.client_id = NEW.client_id AND p.tenant_id = NEW.tenant_id)
	OR (NEW.approved_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.approved_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.approved_authn_context_id IS NOT NULL AND EXISTS (SELECT 1 FROM authn_contexts p WHERE p.id = NEW.approved_authn_context_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.session_id IS NOT NULL AND EXISTS (SELECT 1 FROM sessions p WHERE p.id = NEW.session_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: device_grants'); END;

CREATE TRIGGER IF NOT EXISTS tg_device_grants_xtenant_upd BEFORE UPDATE OF tenant_id, client_id, approved_by_user_id, approved_authn_context_id, session_id ON device_grants
WHEN NOT EXISTS (SELECT 1 FROM api_clients p WHERE p.client_id = NEW.client_id AND p.tenant_id = NEW.tenant_id)
	OR (NEW.approved_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.approved_by_user_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.approved_authn_context_id IS NOT NULL AND EXISTS (SELECT 1 FROM authn_contexts p WHERE p.id = NEW.approved_authn_context_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.session_id IS NOT NULL AND EXISTS (SELECT 1 FROM sessions p WHERE p.id = NEW.session_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: device_grants'); END;

CREATE TRIGGER IF NOT EXISTS tg_refresh_tokens_xtenant_ins BEFORE INSERT ON refresh_tokens
WHEN NOT EXISTS (SELECT 1 FROM api_clients p WHERE p.client_id = NEW.client_id AND p.tenant_id = NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM sessions p WHERE p.id = NEW.session_id AND (p.tenant_id <> NEW.tenant_id OR p.user_id <> NEW.user_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.parent_id IS NOT NULL AND EXISTS (SELECT 1 FROM refresh_tokens p WHERE p.id = NEW.parent_id AND (p.tenant_id <> NEW.tenant_id OR p.family_id <> NEW.family_id)))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: refresh_tokens'); END;

CREATE TRIGGER IF NOT EXISTS tg_refresh_tokens_xtenant_upd BEFORE UPDATE OF tenant_id, client_id, session_id, user_id, parent_id ON refresh_tokens
WHEN NOT EXISTS (SELECT 1 FROM api_clients p WHERE p.client_id = NEW.client_id AND p.tenant_id = NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM sessions p WHERE p.id = NEW.session_id AND (p.tenant_id <> NEW.tenant_id OR p.user_id <> NEW.user_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.parent_id IS NOT NULL AND EXISTS (SELECT 1 FROM refresh_tokens p WHERE p.id = NEW.parent_id AND (p.tenant_id <> NEW.tenant_id OR p.family_id <> NEW.family_id)))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: refresh_tokens'); END;
