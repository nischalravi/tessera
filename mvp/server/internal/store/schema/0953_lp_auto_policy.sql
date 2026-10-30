-- The automatic least-privilege policy of a tenant (issue #664, LP-8; design docs/design/least-privilege-loop.md
-- sections 3, 4 and 11). One row per tenant: the policy that lp/auto.yaml of the access-as-code repository carried
-- when two admins approved its apply (change type lp.auto_policy.apply). Auto mode needs a row; a tenant with none
-- cannot be set to auto. The history is the audit ledger (lp.auto_policy_applied), not this table.
--
-- Tenant-owned like 0001_tenancy.sql: tenant_id on every row, every statement binds it. policy is the canonical
-- JSON of internal/lpauto and policy_sha256 its digest; commit_ref is the repository commit it came from.
CREATE TABLE IF NOT EXISTS lp_auto_policy (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  policy TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL CHECK (length(policy_sha256) = 64),
  commit_ref TEXT NOT NULL CHECK (length(commit_ref) BETWEEN 1 AND 64),
  applied_by TEXT NOT NULL,
  approved_by TEXT NOT NULL DEFAULT '',
  applied_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id)
);
