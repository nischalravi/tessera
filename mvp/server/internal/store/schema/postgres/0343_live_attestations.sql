-- Postgres dialect of schema/0343_live_attestations.sql (issue #217, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). The cross-tenant guard trigger becomes a composite
-- foreign key (tenant_id, revision_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE readiness_live_attestations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  attester TEXT NOT NULL CHECK (length(attester) >= 2),
  reason TEXT NOT NULL CHECK (length(reason) >= 20),
  evidence TEXT NOT NULL CHECK (length(evidence) >= 1),
  item_hash TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  attested_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES connection_revisions (tenant_id, id)
);
