-- Job run history (issue #172): one row per run of a sync, provisioning,
-- validation, dry run, health re-run, JIT sweep or audit anchoring job.
-- A run is inserted as 'running' in its own transaction before the job and
-- finished in another, so a failed job's rollback keeps its record.
-- method/route/path/body let an idempotent run be retried by replaying the
-- same API call; body is the request JSON (no secret-bearing route is a job).
CREATE TABLE IF NOT EXISTS job_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL,
  trigger TEXT NOT NULL CHECK (trigger IN ('manual','schedule','retry')),
  status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed')),
  connection_id TEXT REFERENCES connections (id),
  method TEXT, route TEXT, path TEXT, body TEXT,
  retryable INTEGER NOT NULL DEFAULT 0 CHECK (retryable IN (0,1)),
  retry_of TEXT REFERENCES job_runs (id),
  actor TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  result TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS job_runs_tenant_started ON job_runs(tenant_id, started_at);
CREATE INDEX IF NOT EXISTS job_runs_tenant_status ON job_runs(tenant_id, status);

CREATE TRIGGER IF NOT EXISTS tg_job_runs_xtenant_ins BEFORE INSERT ON job_runs
WHEN (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.retry_of IS NOT NULL AND EXISTS (SELECT 1 FROM job_runs p WHERE p.id = NEW.retry_of AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: job_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_job_runs_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id, retry_of ON job_runs
WHEN (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.retry_of IS NOT NULL AND EXISTS (SELECT 1 FROM job_runs p WHERE p.id = NEW.retry_of AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: job_runs'); END;
