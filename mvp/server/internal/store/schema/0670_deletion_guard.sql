-- Deletion threshold guard (internal/deleteguard): a safety net so a mistake (a bad admin
-- action, a bad source feed, a misconfigured connector or loader) cannot delete everything.
-- When removals of a category in a sliding window exceed a configured threshold, the guard
-- applies only up to the threshold, holds the rest and raises an alert; a second admin
-- releases or discards the held remainder.
--
-- deletion_guard_policies: the tenant's threshold per category (groups, folders,
-- group_members, accounts, identities). A category with no row uses the default in Go, which is
-- on. max_count and max_percent (of the population in scope) may each be NULL (not limited by
-- it); mode is hold_excess | hold_all | off. Rows change only through an applied admin change
-- request (type deletion_guard.update; loosening takes two admins), audited in that transaction.
--
-- deletion_guard_settings: tenant-wide, one row: how long a hold waits before it expires.
--
-- deletion_guard_counters: one row per tenant and category, written first by every check, so
-- concurrent checks serialize on it (a row lock on Postgres, the single writer on SQLite).
--
-- deletion_guard_ledger: the deletions applied in the window. A release of a held item is an
-- approved override and does not write here.
--
-- deletion_holds / deletion_hold_items: the held remainder, item by item, with why, who and
-- where it came from. Items are resolved one by one; the hold's status follows.
CREATE TABLE IF NOT EXISTS deletion_guard_policies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  max_count INTEGER CHECK (max_count IS NULL OR max_count >= 0),
  max_percent REAL CHECK (max_percent IS NULL OR (max_percent >= 0 AND max_percent <= 100)),
  window_minutes INTEGER NOT NULL CHECK (window_minutes BETWEEN 1 AND 10080),
  mode TEXT NOT NULL CHECK (mode IN ('hold_excess','hold_all','off')),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, category)
);

CREATE TABLE IF NOT EXISTS deletion_guard_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  hold_expiry_hours INTEGER NOT NULL CHECK (hold_expiry_hours BETWEEN 1 AND 8760),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deletion_guard_counters (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  seq INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, category)
);

CREATE TABLE IF NOT EXISTS deletion_guard_ledger (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  applied_at TEXT NOT NULL,
  n INTEGER NOT NULL CHECK (n > 0),
  source TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS deletion_guard_ledger_window ON deletion_guard_ledger (tenant_id, category, applied_at);

CREATE TABLE IF NOT EXISTS deletion_holds (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  status TEXT NOT NULL DEFAULT 'held' CHECK (status IN ('held','released','partially_released','discarded','expired')),
  mode TEXT NOT NULL CHECK (mode IN ('hold_excess','hold_all')),
  reason TEXT NOT NULL CHECK (json_valid(reason)),
  actor TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL DEFAULT '',
  correlation_id TEXT NOT NULL,
  item_count INTEGER NOT NULL CHECK (item_count > 0),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  resolved_at TEXT,
  resolved_by TEXT,
  resolution_note TEXT,
  PRIMARY KEY (tenant_id, id),
  CHECK ((status = 'held') = (resolved_at IS NULL))
);
CREATE INDEX IF NOT EXISTS deletion_holds_status ON deletion_holds (tenant_id, status, created_at);

CREATE TABLE IF NOT EXISTS deletion_hold_items (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  hold_id TEXT NOT NULL,
  ord INTEGER NOT NULL CHECK (ord >= 0),
  kind TEXT NOT NULL,
  ref TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'held' CHECK (status IN ('held','released','discarded','gone','failed')),
  note TEXT,
  PRIMARY KEY (tenant_id, hold_id, ord)
);

CREATE TRIGGER IF NOT EXISTS tg_deletion_hold_items_xtenant_ins BEFORE INSERT ON deletion_hold_items
WHEN NOT EXISTS (SELECT 1 FROM deletion_holds h WHERE h.id = NEW.hold_id AND h.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: deletion_hold_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_deletion_hold_items_xtenant_upd BEFORE UPDATE OF tenant_id, hold_id ON deletion_hold_items
WHEN NOT EXISTS (SELECT 1 FROM deletion_holds h WHERE h.id = NEW.hold_id AND h.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: deletion_hold_items'); END;
