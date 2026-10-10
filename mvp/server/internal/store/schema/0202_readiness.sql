-- Deployment readiness: checklist evidence, check runs, reconciliation and
-- scores (design §8.3). Tenant-owned: see 0201_connections.sql.

-- Item states are recomputed by internal/readiness from the evidence below and
-- stored for reporting; they are never the source of a gate decision.
CREATE TABLE IF NOT EXISTS readiness_item_states (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL REFERENCES connection_revisions (id),
  item_id TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('required','recommended','optional')),
  status TEXT NOT NULL CHECK (status IN ('pending','pass','fail','blocked','stale','skipped','not_applicable')),
  source TEXT NOT NULL CHECK (source IN ('attestation','live','data','skip','system')),
  actor_id TEXT, note TEXT, review_by TEXT, check_run_id TEXT REFERENCES readiness_check_runs (id),
  config_hash TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id),
  CHECK (status <> 'skipped' OR (level = 'recommended' AND length(note) >= 20))
);

-- One attestation per item and revision; item_hash binds it to the config
-- fields the item depends on, so a config change makes it stale.
CREATE TABLE IF NOT EXISTS readiness_attestations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL REFERENCES connection_revisions (id),
  item_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  note TEXT NOT NULL CHECK (length(note) >= 10),
  item_hash TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  attested_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id)
);

-- Skipped Recommended items: an accepted gap, visible until un-skipped or expired.
CREATE TABLE IF NOT EXISTS readiness_skips (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL REFERENCES connection_revisions (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  item_id TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level = 'recommended'),
  actor_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) >= 20),
  review_by TEXT NOT NULL,
  template_version TEXT NOT NULL,
  skipped_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id)
);

-- Tenant overlays of the global (embedded) templates.
CREATE TABLE IF NOT EXISTS readiness_overlays (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connector_type TEXT NOT NULL, connection_id TEXT REFERENCES connections (id),
  version INTEGER NOT NULL, body TEXT NOT NULL,
  updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connector_type, connection_id, version)
);

-- Validation and dry-run check runs (DR-3). simulated = 1 for demo scenarios.
CREATE TABLE IF NOT EXISTS readiness_check_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL REFERENCES connection_revisions (id),
  kind TEXT NOT NULL CHECK (kind IN ('validation','scheduled','dry_run')),
  simulated INTEGER NOT NULL DEFAULT 0, agent_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('running','completed','aborted','rate_limited')),
  actor_id TEXT NOT NULL,
  config_hash TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT
);
CREATE INDEX IF NOT EXISTS check_runs_rev ON readiness_check_runs(tenant_id, revision_id, started_at);

-- One row per item and check: the same check id can run with different
-- params for different items (design §8.3 keys results by check only).
-- observed holds counts, versions and dates, never secrets or values.
CREATE TABLE IF NOT EXISTS readiness_check_results (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL REFERENCES readiness_check_runs (id),
  item_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pass','fail','warn','error','skipped','blocked')),
  observed TEXT NOT NULL, message TEXT NOT NULL, duration_ms INTEGER NOT NULL,
  item_hash TEXT NOT NULL,
  simulated INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, run_id, item_id, check_id)
);

-- Dry-run reconciliation runs and findings (DR-4). A reconciliation run
-- shares its id with the dry_run check run that holds its data-check results.
CREATE TABLE IF NOT EXISTS recon_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL REFERENCES connection_revisions (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  mode TEXT NOT NULL CHECK (mode IN ('staging','live')),
  check_run_id TEXT NOT NULL REFERENCES readiness_check_runs (id), counts TEXT, status TEXT NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT
);
CREATE INDEX IF NOT EXISTS recon_runs_rev ON recon_runs(tenant_id, revision_id, started_at);
CREATE TABLE IF NOT EXISTS recon_findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL REFERENCES recon_runs (id),
  connection_id TEXT NOT NULL REFERENCES connections (id), code TEXT NOT NULL, variant TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  count INTEGER NOT NULL, denominator INTEGER NOT NULL,
  samples TEXT NOT NULL, impact TEXT NOT NULL, cause TEXT, item_id TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','resolved')),
  accepted_by TEXT, reason TEXT, expires_at TEXT,
  first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  CHECK (status <> 'accepted' OR length(reason) >= 20)
);
CREATE INDEX IF NOT EXISTS recon_findings_conn ON recon_findings(tenant_id, connection_id, status, severity);
CREATE INDEX IF NOT EXISTS recon_findings_run ON recon_findings(tenant_id, run_id);

-- Readiness score series (DR-5): a row whenever a score changes.
CREATE TABLE IF NOT EXISTS readiness_scores (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  scope TEXT NOT NULL CHECK (scope IN ('connection','tenant')),
  connection_id TEXT REFERENCES connections (id), revision_id TEXT REFERENCES connection_revisions (id),
  computed_at TEXT NOT NULL, score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  band TEXT NOT NULL, breakdown TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS readiness_scores_series ON readiness_scores(tenant_id, scope, connection_id, computed_at);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_readiness_item_states_xtenant_ins BEFORE INSERT ON readiness_item_states
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.check_run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.check_run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_item_states'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_item_states_xtenant_upd BEFORE UPDATE OF tenant_id, revision_id, check_run_id ON readiness_item_states
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.check_run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.check_run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_item_states'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_attestations_xtenant_ins BEFORE INSERT ON readiness_attestations
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_attestations'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_attestations_xtenant_upd BEFORE UPDATE OF tenant_id, revision_id ON readiness_attestations
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_attestations'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_skips_xtenant_ins BEFORE INSERT ON readiness_skips
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_skips'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_skips_xtenant_upd BEFORE UPDATE OF tenant_id, revision_id, connection_id ON readiness_skips
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_skips'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_overlays_xtenant_ins BEFORE INSERT ON readiness_overlays
WHEN (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_overlays'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_overlays_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON readiness_overlays
WHEN (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_overlays'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_check_runs_xtenant_ins BEFORE INSERT ON readiness_check_runs
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_check_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_check_runs_xtenant_upd BEFORE UPDATE OF tenant_id, revision_id ON readiness_check_runs
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_check_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_check_results_xtenant_ins BEFORE INSERT ON readiness_check_results
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_check_results'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_check_results_xtenant_upd BEFORE UPDATE OF tenant_id, run_id ON readiness_check_results
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_check_results'); END;

CREATE TRIGGER IF NOT EXISTS tg_recon_runs_xtenant_ins BEFORE INSERT ON recon_runs
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.check_run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.check_run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: recon_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_recon_runs_xtenant_upd BEFORE UPDATE OF tenant_id, revision_id, connection_id, check_run_id ON recon_runs
WHEN (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.check_run_id IS NOT NULL AND EXISTS (SELECT 1 FROM readiness_check_runs p WHERE p.id = NEW.check_run_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: recon_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_recon_findings_xtenant_ins BEFORE INSERT ON recon_findings
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM recon_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: recon_findings'); END;

CREATE TRIGGER IF NOT EXISTS tg_recon_findings_xtenant_upd BEFORE UPDATE OF tenant_id, run_id, connection_id ON recon_findings
WHEN (NEW.run_id IS NOT NULL AND EXISTS (SELECT 1 FROM recon_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: recon_findings'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_scores_xtenant_ins BEFORE INSERT ON readiness_scores
WHEN (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_scores'); END;

CREATE TRIGGER IF NOT EXISTS tg_readiness_scores_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id, revision_id ON readiness_scores
WHEN (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.revision_id IS NOT NULL AND EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: readiness_scores'); END;

