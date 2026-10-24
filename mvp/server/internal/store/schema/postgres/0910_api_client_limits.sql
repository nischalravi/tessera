-- Postgres dialect of schema/0910_api_client_limits.sql (issue #587). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE api_client_limits (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  client_id TEXT NOT NULL,
  burst INTEGER NOT NULL CHECK (burst BETWEEN 1 AND 100000),
  per_minute INTEGER NOT NULL CHECK (per_minute BETWEEN 1 AND 600000),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, client_id),
  FOREIGN KEY (tenant_id, client_id) REFERENCES api_clients (tenant_id, client_id)
);
