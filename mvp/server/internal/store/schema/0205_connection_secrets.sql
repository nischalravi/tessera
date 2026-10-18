-- Deployment readiness: the sealed credential of a connection revision (DR-13).
--
-- Tenant-owned like every table of 0001_tenancy.sql. secret_ref is the
-- "sealed:<id>" reference kept on connection_revisions; sealed is the
-- AES-256-GCM ciphertext (internal/seal, AAD bound to tenant, table, column
-- and ref), so a blob copied to another row or tenant does not open. The
-- plaintext never touches the database, and no API returns the blob.
CREATE TABLE IF NOT EXISTS connection_secrets (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  secret_ref TEXT NOT NULL,
  sealed BLOB NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, secret_ref)
);
