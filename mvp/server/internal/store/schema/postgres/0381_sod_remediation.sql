-- Postgres dialect of schema/0381_sod_remediation.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); json_valid is IS JSON.

-- +goose Up

CREATE TABLE sod_ruleset_remediation (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  ruleset_id TEXT NOT NULL,
  options TEXT NOT NULL DEFAULT '[]' CHECK (options IS JSON),
  escalate_to_identity_id BIGINT,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, ruleset_id),
  FOREIGN KEY (tenant_id, ruleset_id) REFERENCES sod_rulesets (tenant_id, id),
  FOREIGN KEY (tenant_id, escalate_to_identity_id) REFERENCES identities (tenant_id, id)
);
