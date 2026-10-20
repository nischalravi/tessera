-- Postgres dialect of schema/0354_containment_policy.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE containment_policy_leases (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  policy_id TEXT NOT NULL,
  holder TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, policy_id)
);

CREATE TABLE containment_policy_denials (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  policy_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','active')),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, policy_id, user_id)
);
