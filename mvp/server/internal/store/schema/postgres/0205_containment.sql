-- Postgres dialect of schema/0205_containment.sql (Phase 0 PR14). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE containment_credentials (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL,
  base_url TEXT NOT NULL DEFAULT '',
  org TEXT NOT NULL DEFAULT '',
  token_enc BYTEA NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connection_id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
