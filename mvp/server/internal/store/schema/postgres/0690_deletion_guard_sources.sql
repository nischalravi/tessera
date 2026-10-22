-- Postgres dialect of schema/0690_deletion_guard_sources.sql (kept in parity by TestSchemaParity_SQLiteAndPostgres).

-- +goose Up
CREATE TABLE deletion_guard_source_policies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('connection','loader','vms_source','scim_client')),
  source_id TEXT NOT NULL CHECK (source_id <> ''),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  mode TEXT CHECK (mode IS NULL OR mode IN ('hold_excess','hold_all','off')),
  max_count BIGINT CHECK (max_count IS NULL OR max_count >= 0),
  max_percent DOUBLE PRECISION CHECK (max_percent IS NULL OR (max_percent >= 0 AND max_percent <= 100)),
  window_minutes BIGINT CHECK (window_minutes IS NULL OR window_minutes BETWEEN 1 AND 10080),
  feed_drop_percent DOUBLE PRECISION CHECK (feed_drop_percent IS NULL OR (feed_drop_percent >= 0 AND feed_drop_percent <= 100)),
  feed_empty_check BIGINT CHECK (feed_empty_check IS NULL OR feed_empty_check IN (0,1)),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source_kind, source_id, category),
  CHECK (mode IS NOT NULL OR (max_count IS NULL AND max_percent IS NULL AND window_minutes IS NULL)),
  CHECK (mode IS NULL OR window_minutes IS NOT NULL)
);

CREATE TABLE deletion_guard_source_state (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('connection','loader','vms_source','scim_client')),
  source_id TEXT NOT NULL CHECK (source_id <> ''),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  last_count BIGINT NOT NULL CHECK (last_count >= 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source_kind, source_id, category)
);

CREATE TABLE deletion_guard_source_ledger (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('connection','loader','vms_source','scim_client')),
  source_id TEXT NOT NULL CHECK (source_id <> ''),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  applied_at TEXT NOT NULL,
  n BIGINT NOT NULL CHECK (n > 0),
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX deletion_guard_source_ledger_window
  ON deletion_guard_source_ledger (tenant_id, source_kind, source_id, category, applied_at);
