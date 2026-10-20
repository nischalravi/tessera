-- Postgres dialect of schema/0345_connection_credentials.sql (issue #220, kept in parity with the SQLite
-- file by TestSchemaParity_SQLiteAndPostgres). The cross-tenant guard trigger becomes a composite
-- foreign key (tenant_id, connection_id) -> (tenant_id, id); see 0001_tenancy.sql.
--
-- It replaces connection_secrets and containment_credentials, which Postgres no longer creates:
-- there is nothing to migrate (store.MigrateCredentials moves SQLite rows only).

-- +goose Up

CREATE TABLE connection_credentials (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('bind','containment')),
  ref TEXT NOT NULL DEFAULT '',
  sealed BYTEA NOT NULL,
  base_url TEXT NOT NULL DEFAULT '',
  org TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connection_id, purpose, ref),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
