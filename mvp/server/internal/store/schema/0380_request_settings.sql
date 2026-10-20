-- Tenant-wide access request settings (issue #298, "Request settings").
-- One row per tenant; no row means the defaults in internal/requests (justification
-- required, no duration limits beyond the item's, attachments off, history visible to
-- anyone who can read the graph, request-for-others by permission). The server
-- enforces them when a request is submitted.
--
-- default_hours and max_hours are NULL when unset. for_others is who may request
-- for someone else: nobody, managers (the beneficiary's manager) or permission
-- (anyone holding requests.create_for_others). history_visibility is who sees
-- other people's requests: involved (the people on the request, its approvers
-- and deciders) or readers (also anyone who can read the graph).
-- updated_by is the display name of the admin who saved it; the audit ledger
-- keeps the history.
--
-- Tenant-owned like 0001_tenancy.sql; it references no other tenant-owned row.
CREATE TABLE IF NOT EXISTS request_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  justification_required INTEGER NOT NULL DEFAULT 1 CHECK (justification_required IN (0, 1)),
  justification_min_length INTEGER NOT NULL DEFAULT 1 CHECK (justification_min_length BETWEEN 1 AND 1000),
  default_hours REAL CHECK (default_hours IS NULL OR default_hours > 0),
  max_hours REAL CHECK (max_hours IS NULL OR max_hours > 0),
  attachments_allowed INTEGER NOT NULL DEFAULT 0 CHECK (attachments_allowed IN (0, 1)),
  history_visibility TEXT NOT NULL DEFAULT 'readers' CHECK (history_visibility IN ('involved','readers')),
  for_others TEXT NOT NULL DEFAULT 'permission' CHECK (for_others IN ('nobody','managers','permission')),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
