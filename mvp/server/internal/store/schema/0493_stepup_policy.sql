-- Tenant step-up policy per action (issue #298, "Step-up per action").
-- One row per tenant; no row means the code's own requirements, which are the
-- floor: an entry can add step-up to an action or make it stricter, never remove
-- or weaken what the code requires (internal/auth StepUpTable). entries is a
-- JSON object action -> {acr, max_age_s}; the action is a permission whose
-- state-changing routes the policy covers, and the server validates the
-- entries against the routes it has.
-- updated_by is the display name of the admin who saved it; the audit ledger
-- keeps the history.
--
-- Tenant-owned like 0001_tenancy.sql; it references no other tenant-owned row.
CREATE TABLE IF NOT EXISTS stepup_policy (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  entries TEXT NOT NULL CHECK (json_valid(entries)),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
