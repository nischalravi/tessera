-- One sealed credential store for every provider secret a connection holds
-- (issue #220). It replaces connection_secrets (the LDAP bind password of a
-- readiness revision, DR-13) and containment_credentials (the kill-switch
-- provider token, #106); store.MigrateCredentials moves their rows and drops
-- them.
--
-- A row is one secret of one connection for one purpose:
--   bind         the credential a readiness revision runs its live checks with;
--                ref is the "sealed:<id>" reference kept on the revision
--   containment  the token the kill switch calls the provider with; ref is ''
-- sealed is AES-256-GCM ciphertext (internal/seal) whose AAD binds tenant,
-- table, column, connection, purpose and ref (store.CredentialAAD), so a blob
-- copied to another row, purpose or tenant does not open. The plaintext never
-- touches the database and no API returns the blob. base_url and org are plain
-- configuration (empty for bind).
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's connection.
CREATE TABLE IF NOT EXISTS connection_credentials (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  purpose TEXT NOT NULL CHECK (purpose IN ('bind','containment')),
  ref TEXT NOT NULL DEFAULT '',
  sealed BLOB NOT NULL,
  base_url TEXT NOT NULL DEFAULT '',
  org TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connection_id, purpose, ref)
);

CREATE TRIGGER IF NOT EXISTS tg_connection_credentials_xtenant_ins BEFORE INSERT ON connection_credentials
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connection_credentials'); END;

CREATE TRIGGER IF NOT EXISTS tg_connection_credentials_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON connection_credentials
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connection_credentials'); END;
