-- Postgres dialect of schema/0670_deletion_guard.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). json_valid is IS JSON; the hold items reference their
-- hold by (tenant_id, id), so no row can point at another tenant's hold.

-- +goose Up

CREATE TABLE deletion_guard_policies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  max_count BIGINT CHECK (max_count IS NULL OR max_count >= 0),
  max_percent DOUBLE PRECISION CHECK (max_percent IS NULL OR (max_percent >= 0 AND max_percent <= 100)),
  window_minutes BIGINT NOT NULL CHECK (window_minutes BETWEEN 1 AND 10080),
  mode TEXT NOT NULL CHECK (mode IN ('hold_excess','hold_all','off')),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, category)
);

CREATE TABLE deletion_guard_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  hold_expiry_hours BIGINT NOT NULL CHECK (hold_expiry_hours BETWEEN 1 AND 8760),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE deletion_guard_counters (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  seq BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, category)
);

CREATE TABLE deletion_guard_ledger (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  applied_at TEXT NOT NULL,
  n BIGINT NOT NULL CHECK (n > 0),
  source TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX deletion_guard_ledger_window ON deletion_guard_ledger (tenant_id, category, applied_at);

CREATE TABLE deletion_holds (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  status TEXT NOT NULL DEFAULT 'held' CHECK (status IN ('held','released','partially_released','discarded','expired')),
  mode TEXT NOT NULL CHECK (mode IN ('hold_excess','hold_all')),
  reason TEXT NOT NULL CHECK (reason IS JSON),
  actor TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL DEFAULT '',
  correlation_id TEXT NOT NULL,
  item_count BIGINT NOT NULL CHECK (item_count > 0),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  resolved_at TEXT,
  resolved_by TEXT,
  resolution_note TEXT,
  PRIMARY KEY (tenant_id, id),
  CHECK ((status = 'held') = (resolved_at IS NULL))
);
CREATE INDEX deletion_holds_status ON deletion_holds (tenant_id, status, created_at);

CREATE TABLE deletion_hold_items (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  hold_id TEXT NOT NULL,
  ord BIGINT NOT NULL CHECK (ord >= 0),
  kind TEXT NOT NULL,
  ref TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'held' CHECK (status IN ('held','released','discarded','gone','failed')),
  note TEXT,
  PRIMARY KEY (tenant_id, hold_id, ord),
  FOREIGN KEY (tenant_id, hold_id) REFERENCES deletion_holds (tenant_id, id)
);
