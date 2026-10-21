-- Tenant-level SoD page configuration (issue #298, "SoD page configuration").
-- One row per tenant; no row means every column and filter is shown.
-- visible_columns and visible_filters are JSON lists of keys (risk, function,
-- entitlement, ruleset, mitigating_control, business_process; the server
-- validates them) naming what SoD reviewers see on the conflicts page. The API
-- refuses an empty column list (a page with no columns shows nothing); the table
-- does not.
-- updated_by is the display name of the admin who saved it; the audit ledger
-- keeps the history.
--
-- Tenant-owned like 0001_tenancy.sql; it references no other tenant-owned row.
CREATE TABLE IF NOT EXISTS sod_view_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  visible_columns TEXT NOT NULL CHECK (json_valid(visible_columns)),
  visible_filters TEXT NOT NULL CHECK (json_valid(visible_filters)),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
