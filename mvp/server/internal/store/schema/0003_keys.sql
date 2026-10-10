-- Phase 0 PR2: signing keys (design §7.4, §7.5, §10.6).
--
-- tenant_signing_keys is tenant-owned. platform_keys is GLOBAL (listed in
-- store.GlobalTables). Private keys are stored only sealed under the KEK
-- (internal/seal), with an AAD that binds tenant, table, column and kid.
-- Rows are never deleted: retired and revoked keys stay as evidence.
CREATE TABLE IF NOT EXISTS tenant_signing_keys (
  kid TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  purpose TEXT NOT NULL CHECK (purpose IN ('access_token','idp_client_auth')),
  alg TEXT NOT NULL DEFAULT 'ES256' CHECK (alg = 'ES256'),
  public_jwk TEXT NOT NULL,
  private_key_enc BLOB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('next','active','retired','revoked')),
  created_at TEXT NOT NULL, activated_at TEXT, retired_at TEXT
);
CREATE INDEX IF NOT EXISTS tenant_signing_keys_tenant ON tenant_signing_keys(tenant_id, purpose, status);
-- at most one active and one next key per tenant and purpose
CREATE UNIQUE INDEX IF NOT EXISTS tenant_signing_keys_one_active ON tenant_signing_keys(tenant_id, purpose) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS tenant_signing_keys_one_next ON tenant_signing_keys(tenant_id, purpose) WHERE status = 'next';

-- GLOBAL
CREATE TABLE IF NOT EXISTS platform_keys (
  kid TEXT PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose = 'audit_checkpoint'),
  alg TEXT NOT NULL DEFAULT 'EdDSA' CHECK (alg = 'EdDSA'),
  public_jwk TEXT NOT NULL,
  private_key_enc BLOB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','retired','revoked')),
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS platform_keys_one_active ON platform_keys(purpose) WHERE status = 'active';
