-- Postgres dialect of schema/0922_lp_denials.sql (issue #662, kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). revocation_id is deliberately not a foreign key (the history outlives it);
-- see 0001_tenancy.sql for the tenant rules.

-- +goose Up

CREATE TABLE lp_denial_hooks (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  secret_sha256 TEXT NOT NULL CHECK (length(secret_sha256) = 64),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  rotated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id)
);

CREATE TABLE lp_denials (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('cloudtrail', 'idp')),
  event_id TEXT NOT NULL,
  principal_arn TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL DEFAULT '',
  occurred_at TEXT,
  arrived_at TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('restore_requested', 'action_not_removed')),
  revocation_id TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX lp_denials_event ON lp_denials (tenant_id, source, event_id);
CREATE INDEX lp_denials_arrived ON lp_denials (tenant_id, arrived_at);
