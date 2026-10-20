-- Postgres dialect of schema/0358_oauth.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE api_clients (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 3 AND 64),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('first_party_cli','machine')),
  grant_types TEXT NOT NULL DEFAULT '[]',
  token_endpoint_auth_method TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('none','private_key_jwt')),
  jwks TEXT,
  dpop_required BIGINT NOT NULL DEFAULT 1 CHECK (dpop_required IN (0, 1)),
  allowed_scopes TEXT NOT NULL DEFAULT '[]',
  roles TEXT NOT NULL DEFAULT '[]',
  owner_user_id TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at TEXT NOT NULL, last_used_at TEXT, change_request_id TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, client_id),
  -- every machine client has an owner (the NHI owner rule)
  CHECK (kind <> 'machine' OR owner_user_id IS NOT NULL),
  -- the CLI is a public client and always uses DPoP
  CHECK (kind <> 'first_party_cli' OR (token_endpoint_auth_method = 'none' AND dpop_required = 1)),
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX api_clients_tenant ON api_clients(tenant_id);

CREATE TABLE device_grants (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  client_id TEXT NOT NULL,
  device_code_hash TEXT NOT NULL CHECK (length(device_code_hash) = 64),
  user_code_hash TEXT NOT NULL CHECK (length(user_code_hash) = 64),
  scope TEXT NOT NULL,
  required_tessera_acr TEXT, max_age BIGINT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired','consumed')),
  request_ip TEXT, request_user_agent TEXT,
  poll_interval BIGINT NOT NULL DEFAULT 5, last_polled_at TEXT,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  approved_by_user_id TEXT,
  approved_authn_context_id TEXT,
  approved_at TEXT,
  session_id TEXT,
  lookup_failures BIGINT NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, device_code_hash),
  FOREIGN KEY (tenant_id, approved_by_user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_authn_context_id) REFERENCES authn_contexts (tenant_id, id),
  FOREIGN KEY (tenant_id, session_id) REFERENCES sessions (tenant_id, id),
  FOREIGN KEY (tenant_id, client_id) REFERENCES api_clients (tenant_id, client_id)
);
CREATE INDEX device_grants_user_code ON device_grants(tenant_id, user_code_hash);
-- a user code is unique among the pending grants of a tenant
CREATE UNIQUE INDEX device_grants_pending_user_code ON device_grants(tenant_id, user_code_hash) WHERE status = 'pending';

CREATE TABLE refresh_tokens (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
  family_id TEXT NOT NULL, parent_id TEXT,
  session_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt) BETWEEN 20 AND 64),
  scope TEXT NOT NULL,
  issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL,
  used_at TEXT, revoked_at TEXT, revoked_reason TEXT,
  UNIQUE (tenant_id, token_hash),
  CHECK (expires_at <= absolute_expires_at),
  UNIQUE (tenant_id, family_id, id),
  FOREIGN KEY (tenant_id, client_id) REFERENCES api_clients (tenant_id, client_id),
  FOREIGN KEY (tenant_id, session_id) REFERENCES sessions (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, family_id, parent_id) REFERENCES refresh_tokens (tenant_id, family_id, id)
);
CREATE INDEX refresh_tokens_family ON refresh_tokens(tenant_id, family_id);
CREATE INDEX refresh_tokens_session ON refresh_tokens(tenant_id, session_id);

-- ---------------------------------------------------------------- guard triggers
