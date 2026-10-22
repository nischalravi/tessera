-- Postgres dialect of schema/0621_agent_seal_keys.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE agent_seal_keys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  agent_id TEXT NOT NULL,
  public_key BYTEA NOT NULL CHECK (length(public_key) = 32),
  key_id TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  UNIQUE (tenant_id, agent_id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES directory_agents (tenant_id, id)
);
