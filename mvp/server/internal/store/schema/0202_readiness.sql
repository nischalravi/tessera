-- Deployment readiness: checklist evidence (design §8.3).

-- Item states are recomputed by internal/readiness from the evidence below and
-- stored for reporting; they are never the source of a gate decision.
CREATE TABLE IF NOT EXISTS readiness_item_states (
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  revision_id TEXT NOT NULL REFERENCES connection_revisions(id),
  item_id TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('required','recommended','optional')),
  status TEXT NOT NULL CHECK (status IN ('pending','pass','fail','blocked','stale','skipped','not_applicable')),
  source TEXT NOT NULL CHECK (source IN ('attestation','live','data','skip','system')),
  actor_id TEXT, note TEXT, review_by TEXT, check_run_id TEXT,
  config_hash TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id),
  CHECK (status <> 'skipped' OR (level = 'recommended' AND length(note) >= 20))
);

-- One attestation per item and revision; item_hash binds it to the config
-- fields the item depends on, so a config change makes it stale.
CREATE TABLE IF NOT EXISTS readiness_attestations (
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  revision_id TEXT NOT NULL REFERENCES connection_revisions(id),
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
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  revision_id TEXT NOT NULL REFERENCES connection_revisions(id),
  connection_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level = 'recommended'),
  actor_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) >= 20),
  review_by TEXT NOT NULL,
  template_version TEXT NOT NULL,
  skipped_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id)
);

CREATE TABLE IF NOT EXISTS readiness_overlays (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  connector_type TEXT NOT NULL, connection_id TEXT,
  version INTEGER NOT NULL, body TEXT NOT NULL,
  updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connector_type, connection_id, version)
);

-- Validation and dry-run check runs (DR-3). simulated = 1 for demo scenarios.
CREATE TABLE IF NOT EXISTS readiness_check_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  revision_id TEXT NOT NULL,
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
  tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002',
  run_id TEXT NOT NULL REFERENCES readiness_check_runs(id),
  item_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pass','fail','warn','error','skipped','blocked')),
  observed TEXT NOT NULL, message TEXT NOT NULL, duration_ms INTEGER NOT NULL,
  item_hash TEXT NOT NULL,
  simulated INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, run_id, item_id, check_id)
);
