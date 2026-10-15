-- Identity containment (issue #106): the provider credential a connection's
-- kill-switch calls use (revoke sessions, refresh tokens, OAuth grants).
--
-- One row per connection. token_enc is the provider token sealed with
-- internal/seal (AES-256-GCM, AAD bound to tenant, table, column and
-- connection_id); the plaintext is never stored or logged. base_url and org
-- are plain configuration; every outbound call goes through internal/safehttp.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's connection.
CREATE TABLE IF NOT EXISTS containment_credentials (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  base_url TEXT NOT NULL DEFAULT '',
  org TEXT NOT NULL DEFAULT '',
  token_enc BLOB NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connection_id)
);

CREATE TRIGGER IF NOT EXISTS tg_containment_credentials_xtenant_ins BEFORE INSERT ON containment_credentials
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: containment_credentials'); END;

CREATE TRIGGER IF NOT EXISTS tg_containment_credentials_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON containment_credentials
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: containment_credentials'); END;
