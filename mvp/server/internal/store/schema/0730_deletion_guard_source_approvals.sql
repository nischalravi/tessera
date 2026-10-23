-- Two-admin approval of a source's deletion-guard override (issue #494). The deletion guard keeps an
-- overridden source inside the category's tenant-wide budget (#485) unless the override took two
-- admins to set as looser than the category. Whether that happened is decided when the change is
-- approved and recorded here, not re-derived from the category later: a category tightened by one
-- admin must not turn every existing override into an "approved loosening".
--
-- deletion_guard_source_approvals: a row means the override of this source and category was set,
-- looser than the category, by a change two admins approved. No row (every override from before this
-- table, every single-admin override) means the override also draws on the category's budget. The row
-- goes when the override is removed or set again. source_id names a row of another table by kind with
-- no foreign key, like 0690.
CREATE TABLE IF NOT EXISTS deletion_guard_source_approvals (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('connection','loader','vms_source','scim_client')),
  source_id TEXT NOT NULL CHECK (source_id <> ''),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  approved_by TEXT,
  approved_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source_kind, source_id, category)
);
