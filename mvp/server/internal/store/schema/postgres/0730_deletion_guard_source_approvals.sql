-- Postgres dialect of schema/0730_deletion_guard_source_approvals.sql (kept in parity by TestSchemaParity_SQLiteAndPostgres).

-- +goose Up
CREATE TABLE deletion_guard_source_approvals (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('connection','loader','vms_source','scim_client')),
  source_id TEXT NOT NULL CHECK (source_id <> ''),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  approved_by TEXT,
  approved_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source_kind, source_id, category)
);
