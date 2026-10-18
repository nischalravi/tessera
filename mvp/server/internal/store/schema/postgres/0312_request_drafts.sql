-- Postgres dialect of schema/0312_request_drafts.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE request_drafts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT NOT NULL,
  beneficiary_ids TEXT NOT NULL DEFAULT '[]',
  items TEXT NOT NULL DEFAULT '[]',
  duration_hours DOUBLE PRECISION CHECK (duration_hours IS NULL OR duration_hours > 0),
  justification TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_request_drafts_tenant_user ON request_drafts (tenant_id, user_id, updated_at);
