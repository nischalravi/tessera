-- Postgres variant of 0953_lp_auto_policy.sql (issue #664, LP-8). One row per tenant; no foreign keys beyond the
-- tenant, so no cross-tenant triggers are needed.

-- +goose Up
CREATE TABLE lp_auto_policy (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  policy TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL CHECK (length(policy_sha256) = 64),
  commit_ref TEXT NOT NULL CHECK (length(commit_ref) BETWEEN 1 AND 64),
  applied_by TEXT NOT NULL,
  approved_by TEXT NOT NULL DEFAULT '',
  applied_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id)
);
