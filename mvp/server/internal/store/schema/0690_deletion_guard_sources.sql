-- Per-source settings of the deletion threshold guard (internal/deleteguard): a source (a connection,
-- a group loader, a VMS feed, a SCIM client) may carry its own thresholds, and its own feed sanity
-- checks, in place of the category's.
--
-- deletion_guard_source_policies: one row per source and category. mode NULL inherits the category's
-- thresholds (max_count, max_percent and window_minutes are then NULL too); otherwise the row is a
-- complete threshold for that source's deletions. feed_drop_percent NULL is the default (20) and
-- feed_empty_check NULL is on: how far the source's record count may fall against its last good run
-- before the removals it asks for are held, and whether an empty feed is held whatever the percent.
-- Rows change only through an applied admin change request (deletion_guard.update; loosening takes
-- two admins). source_id names a row of another table by kind with no foreign key (a deleted source
-- keeps no meaning here), so the tenant is the only guard.
--
-- deletion_guard_source_state: the record count of the source's last good run per category, the
-- basis the next run's drop is measured against.
--
-- deletion_guard_source_ledger: the deletions a source's requests applied in the window (the tenant
-- ledger counts them too), so a source with its own threshold is measured by what it did itself.
CREATE TABLE IF NOT EXISTS deletion_guard_source_policies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('connection','loader','vms_source','scim_client')),
  source_id TEXT NOT NULL CHECK (source_id <> ''),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  mode TEXT CHECK (mode IS NULL OR mode IN ('hold_excess','hold_all','off')),
  max_count INTEGER CHECK (max_count IS NULL OR max_count >= 0),
  max_percent REAL CHECK (max_percent IS NULL OR (max_percent >= 0 AND max_percent <= 100)),
  window_minutes INTEGER CHECK (window_minutes IS NULL OR window_minutes BETWEEN 1 AND 10080),
  feed_drop_percent REAL CHECK (feed_drop_percent IS NULL OR (feed_drop_percent >= 0 AND feed_drop_percent <= 100)),
  feed_empty_check INTEGER CHECK (feed_empty_check IS NULL OR feed_empty_check IN (0,1)),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source_kind, source_id, category),
  CHECK (mode IS NOT NULL OR (max_count IS NULL AND max_percent IS NULL AND window_minutes IS NULL)),
  CHECK (mode IS NULL OR window_minutes IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS deletion_guard_source_state (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('connection','loader','vms_source','scim_client')),
  source_id TEXT NOT NULL CHECK (source_id <> ''),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  last_count INTEGER NOT NULL CHECK (last_count >= 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source_kind, source_id, category)
);

CREATE TABLE IF NOT EXISTS deletion_guard_source_ledger (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('connection','loader','vms_source','scim_client')),
  source_id TEXT NOT NULL CHECK (source_id <> ''),
  category TEXT NOT NULL CHECK (category IN ('groups','folders','group_members','accounts','identities')),
  applied_at TEXT NOT NULL,
  n INTEGER NOT NULL CHECK (n > 0),
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS deletion_guard_source_ledger_window
  ON deletion_guard_source_ledger (tenant_id, source_kind, source_id, category, applied_at);
