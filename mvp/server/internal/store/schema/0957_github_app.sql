-- GitHub App for policy pull requests (issue #656, AC-10; design docs/design/differentiators-plan.md, AC-10): the per-tenant
-- App credentials that replace the stored personal token, and the check run and comment last posted on each pull request.
--
-- github_app_settings: one row per tenant (none: the feature is off). app_id is the App's numeric id and installation_id
-- the installation on the tenant's organization; repo ("owner/name") is the one repository the installation token is
-- limited to. key_enc is the App's private key (PEM), sealed with internal/seal (AES-256-GCM, AAD bound to tenant, table and
-- column); it is never returned by the API, only key_fingerprint (the SHA-256 fingerprint GitHub shows for the key, not
-- secret) and the time it was set, so it can be rotated and compared with the App's page.
--
-- github_pr_checks: for each (repo, pull request) the commit the last check run was posted on, the check run id and the
-- comment id, so a re-run updates the comment in place instead of adding another, and a re-run on the same commit updates
-- its check run. conclusion and diff_sha256 are those of the last preview.
--
-- Tenant-owned: tenant_id on every row and first in every key. Neither table references another tenant table, so no
-- cross-tenant guard trigger is needed. Postgres: migration 0965.
CREATE TABLE IF NOT EXISTS github_app_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  app_id TEXT NOT NULL DEFAULT '' CHECK (length(app_id) <= 20),
  installation_id INTEGER NOT NULL DEFAULT 0 CHECK (installation_id >= 0),
  repo TEXT NOT NULL DEFAULT '' CHECK (length(repo) <= 201),
  key_enc BLOB,
  key_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(key_fingerprint) <= 64),
  key_set_at TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS github_pr_checks (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  repo TEXT NOT NULL CHECK (length(repo) <= 201),
  pull_number INTEGER NOT NULL CHECK (pull_number >= 1),
  head_sha TEXT NOT NULL CHECK (length(head_sha) <= 64),
  check_run_id INTEGER NOT NULL DEFAULT 0,
  comment_id INTEGER NOT NULL DEFAULT 0,
  conclusion TEXT NOT NULL CHECK (conclusion IN ('success', 'failure', 'neutral')),
  diff_sha256 TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, repo, pull_number)
);
