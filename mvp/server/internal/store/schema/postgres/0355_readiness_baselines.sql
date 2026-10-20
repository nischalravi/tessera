-- Postgres dialect of schema/0355_readiness_baselines.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE readiness_baselines (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  score BIGINT NOT NULL CHECK (score BETWEEN 0 AND 100),
  config_hash TEXT NOT NULL,
  snapshot TEXT NOT NULL,
  last_counts TEXT,
  last_run_id TEXT,
  last_run_at TEXT,
  fail_streak BIGINT NOT NULL DEFAULT 0 CHECK (fail_streak >= 0),
  degraded_reason TEXT,
  degraded_at TEXT,
  upgrade_pin TEXT,
  upgrade_seen_at TEXT,
  PRIMARY KEY (tenant_id, revision_id),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES connection_revisions (tenant_id, id)
);
