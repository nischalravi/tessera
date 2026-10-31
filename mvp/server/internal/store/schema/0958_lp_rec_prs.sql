-- Right-sizing recommendations as pull requests (issue #665, LP-9; design docs/design/differentiators-plan.md, LP-9): the pull
-- request opened on the policy repository for each recommendation, so the same recommendation never opens a second one.
--
-- lp_rec_prs: one row per (recommendation, repository). rec_id is the recommendation's id ("grant-<edge id>"; the
-- recommendation itself is computed from usage on demand, not stored). branch is the branch Tessera pushed, pull_number
-- the pull request (0 until one exists, when only the branch does) and head_sha the commit it was last updated to; state is open until a request finds the pull request
-- closed, when the next request opens a new one on the same branch. role_key is the roles/<key>.yaml file edited and
-- body_sha256 the digest of the body last posted, so an unchanged re-run is visible. Rows are never deleted.
--
-- lp_rec_pr_attempts (migration 0959): one row per request that reached the point of writing to the repository, reserved in
-- a write transaction before GitHub is called, so the hourly cap counts every attempt (failed ones too) and cannot be
-- bypassed by closing a pull request or by concurrent requests.
--
-- Tenant-owned: tenant_id on every row and first in the key. The table references no other tenant table, so no
-- cross-tenant guard trigger is needed. Postgres: migration 0966.
CREATE TABLE IF NOT EXISTS lp_rec_prs (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  rec_id TEXT NOT NULL CHECK (length(rec_id) BETWEEN 1 AND 64),
  repo TEXT NOT NULL CHECK (length(repo) <= 201),
  branch TEXT NOT NULL CHECK (length(branch) BETWEEN 1 AND 200),
  pull_number INTEGER NOT NULL CHECK (pull_number >= 0),
  head_sha TEXT NOT NULL CHECK (length(head_sha) <= 64),
  role_key TEXT NOT NULL DEFAULT '' CHECK (length(role_key) <= 200),
  body_sha256 TEXT NOT NULL DEFAULT '' CHECK (length(body_sha256) <= 64),
  state TEXT NOT NULL CHECK (state IN ('open', 'closed')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, rec_id, repo)
);
