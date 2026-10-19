-- Postgres dialect of schema/0003_keys.sql (Phase 0 PR14). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE tenant_signing_keys (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  kid TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  purpose TEXT NOT NULL CHECK (purpose IN ('access_token','idp_client_auth')),
  alg TEXT NOT NULL DEFAULT 'ES256' CHECK (alg = 'ES256'),
  public_jwk TEXT NOT NULL,
  private_key_enc BYTEA NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('next','active','retired','revoked')),
  created_at TEXT NOT NULL, activated_at TEXT, retired_at TEXT
);
CREATE INDEX tenant_signing_keys_tenant ON tenant_signing_keys(tenant_id, purpose, status);
-- at most one active and one next key per tenant and purpose
CREATE UNIQUE INDEX tenant_signing_keys_one_active ON tenant_signing_keys(tenant_id, purpose) WHERE status = 'active';
CREATE UNIQUE INDEX tenant_signing_keys_one_next ON tenant_signing_keys(tenant_id, purpose) WHERE status = 'next';

-- GLOBAL
CREATE TABLE platform_keys (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  kid TEXT PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose = 'audit_checkpoint'),
  alg TEXT NOT NULL DEFAULT 'EdDSA' CHECK (alg = 'EdDSA'),
  public_jwk TEXT NOT NULL,
  private_key_enc BYTEA NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','retired','revoked')),
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX platform_keys_one_active ON platform_keys(purpose) WHERE status = 'active';
