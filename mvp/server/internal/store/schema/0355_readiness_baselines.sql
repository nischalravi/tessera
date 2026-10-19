-- Deployment readiness drift (DR-9, design §7.4/§7.5): the baseline a live
-- revision is compared with, plus the monitoring state of its scheduled
-- re-runs. Tenant-owned: see 0201_connections.sql.
--
-- The baseline columns (captured_at .. snapshot) are written once, at
-- activation (or at the first scheduled run for a revision activated before
-- this table existed). The monitor columns are updated by every scheduled run:
-- the object counts of the previous run (drift is measured between consecutive
-- runs), the run last evaluated (so a run is never counted twice), the streak
-- of consecutive failing runs, the reason a revision is degraded, and when a
-- newer template minor release was first seen (its 30-day grace period).
CREATE TABLE IF NOT EXISTS readiness_baselines (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL REFERENCES connection_revisions (id),
  captured_at TEXT NOT NULL,
  score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  config_hash TEXT NOT NULL,
  snapshot TEXT NOT NULL,
  last_counts TEXT,
  last_run_id TEXT,
  last_run_at TEXT,
  fail_streak INTEGER NOT NULL DEFAULT 0 CHECK (fail_streak >= 0),
  degraded_reason TEXT,
  degraded_at TEXT,
  upgrade_pin TEXT,
  upgrade_seen_at TEXT,
  PRIMARY KEY (tenant_id, revision_id)
);

CREATE TRIGGER IF NOT EXISTS tg_readiness_baselines_xtenant_ins BEFORE INSERT ON readiness_baselines
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_baselines'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_baselines_xtenant_upd BEFORE UPDATE OF tenant_id, revision_id ON readiness_baselines
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_baselines'); END;
