-- Postgres dialect of schema/0281_job_runs.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE job_runs (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL,
  trigger TEXT NOT NULL CHECK (trigger IN ('manual','schedule','retry')),
  status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed')),
  connection_id TEXT,
  method TEXT, route TEXT, path TEXT, body TEXT,
  retryable BIGINT NOT NULL DEFAULT 0 CHECK (retryable IN (0,1)),
  retry_of TEXT,
  actor TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  result TEXT,
  error TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id),
  FOREIGN KEY (tenant_id, retry_of) REFERENCES job_runs (tenant_id, id)
);
CREATE INDEX job_runs_tenant_started ON job_runs (tenant_id, started_at);
CREATE INDEX job_runs_tenant_status ON job_runs (tenant_id, status);
