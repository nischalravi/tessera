-- The claim a check run request holds on a pull request while it posts to GitHub (issue #781, AC-10): one row per
-- (repo, pull request), inserted in its own write transaction before GitHub is called and deleted when the outcome is
-- recorded, so concurrent requests cannot both create a check run and a comment. A claim older than its time to live (a
-- request that died) is replaced. Tenant-owned; no reference to another tenant table. Postgres: migration 0968.
CREATE TABLE IF NOT EXISTS github_pr_check_claims (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  repo TEXT NOT NULL CHECK (length(repo) <= 201),
  pull_number INTEGER NOT NULL CHECK (pull_number >= 1),
  claimed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, repo, pull_number)
);
