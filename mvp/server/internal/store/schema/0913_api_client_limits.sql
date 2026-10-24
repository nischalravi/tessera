-- Per-client API rate limit overrides (issue #587). A machine client without a row
-- gets the tenant-wide default (TESSERA_API_CLIENT_RATE_BURST and
-- TESSERA_API_CLIENT_RATE_PER_MINUTE); a row replaces it for that client:
-- a token bucket of `burst` requests, refilled at `per_minute` requests a minute.
--
-- Tenant-owned like 0001_tenancy.sql. The guard triggers at the end tie a row to a
-- client of the same tenant, so another tenant's client cannot be named (Postgres:
-- a composite foreign key).
CREATE TABLE IF NOT EXISTS api_client_limits (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  client_id TEXT NOT NULL,
  burst INTEGER NOT NULL CHECK (burst BETWEEN 1 AND 100000),
  per_minute INTEGER NOT NULL CHECK (per_minute BETWEEN 1 AND 600000),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, client_id)
);

CREATE TRIGGER IF NOT EXISTS tg_api_client_limits_xtenant_ins BEFORE INSERT ON api_client_limits
WHEN NOT EXISTS (SELECT 1 FROM api_clients p WHERE p.client_id = NEW.client_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: api_client_limits'); END;

CREATE TRIGGER IF NOT EXISTS tg_api_client_limits_xtenant_upd BEFORE UPDATE OF tenant_id, client_id ON api_client_limits
WHEN NOT EXISTS (SELECT 1 FROM api_clients p WHERE p.client_id = NEW.client_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: api_client_limits'); END;
