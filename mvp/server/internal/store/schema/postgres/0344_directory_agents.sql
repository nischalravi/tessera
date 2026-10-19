-- Postgres dialect of schema/0250_directory_agents.sql (DR-11, kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.
-- cert_pin and token_hash are the two global bearer-hash lookups (GlobalHashLookups); rls.sql
-- gives them a SELECT-only lookup_by_hash policy.

-- +goose Up

CREATE TABLE directory_agents (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','active','revoked')),
  cert_pin TEXT UNIQUE CHECK (cert_pin IS NULL OR length(cert_pin) = 64),
  hostname TEXT, os TEXT, version TEXT, allowlist_hash TEXT,
  last_seen_at TEXT, enrolled_at TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  revoked_at TEXT, revoked_by TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name)
);
CREATE INDEX directory_agents_tenant ON directory_agents(tenant_id);

CREATE TABLE agent_enrolments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  agent_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, agent_id) REFERENCES directory_agents (tenant_id, id)
);
CREATE INDEX agent_enrolments_tenant ON agent_enrolments(tenant_id, agent_id);

-- connections.agent_id (0201) names a directory agent of the same tenant.
ALTER TABLE connections ADD FOREIGN KEY (tenant_id, agent_id) REFERENCES directory_agents (tenant_id, id);
