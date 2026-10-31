-- Attempts to open or update a right-sizing pull request (issue #665, LP-9): the rows the hourly cap counts. One row is
-- inserted, in a write transaction that first locks the tenant's GitHub App settings row, before GitHub is called, so
-- concurrent requests cannot both pass the cap and a failed or repeated request still counts. Tenant-owned; no reference to
-- another tenant table, so no cross-tenant guard trigger. Postgres: migration 0967.
CREATE TABLE IF NOT EXISTS lp_rec_pr_attempts (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  rec_id TEXT NOT NULL CHECK (length(rec_id) BETWEEN 1 AND 64),
  repo TEXT NOT NULL CHECK (length(repo) <= 201),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS lp_rec_pr_attempts_created ON lp_rec_pr_attempts (tenant_id, created_at);
