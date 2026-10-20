-- Postgres dialect of schema/0420_role_mining.sql (issue #298, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE role_mining_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  status TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
  params TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL DEFAULT '',
  people BIGINT NOT NULL DEFAULT 0,
  entitlements BIGINT NOT NULL DEFAULT 0,
  candidates BIGINT NOT NULL DEFAULT 0,
  skipped_existing BIGINT NOT NULL DEFAULT 0,
  truncated BIGINT NOT NULL DEFAULT 0 CHECK (truncated IN (0,1)),
  error TEXT NOT NULL DEFAULT '',
  requested_by TEXT,
  requested_actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_role_mining_runs_tenant ON role_mining_runs (tenant_id, created_at);

CREATE TABLE role_mining_candidates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL,
  rank_no BIGINT NOT NULL,
  name TEXT NOT NULL,
  entitlements TEXT NOT NULL,
  members TEXT NOT NULL,
  outliers TEXT NOT NULL,
  coverage BIGINT NOT NULL,
  rule TEXT,
  confidence BIGINT NOT NULL,
  cohesion BIGINT NOT NULL,
  similar_role_id TEXT,
  similarity BIGINT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','dismissed')),
  decided_by TEXT,
  decided_actor TEXT,
  decided_at TEXT,
  decision_reason TEXT,
  role_id TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, run_id, rank_no),
  FOREIGN KEY (tenant_id, run_id) REFERENCES role_mining_runs (tenant_id, id),
  FOREIGN KEY (tenant_id, similar_role_id) REFERENCES business_roles (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, role_id) REFERENCES business_roles (tenant_id, id)
);
CREATE INDEX ix_role_mining_candidates_run ON role_mining_candidates (tenant_id, run_id);
