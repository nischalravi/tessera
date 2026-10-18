-- Postgres dialect of schema/0202_readiness.sql (Phase 0 PR14). See 0001_tenancy.sql.
-- readiness_check_runs is created before readiness_item_states, which
-- references it.

-- +goose Up

CREATE TABLE readiness_check_runs (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('validation','scheduled','dry_run')),
  simulated BIGINT NOT NULL DEFAULT 0, agent_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('running','completed','aborted','rate_limited')),
  actor_id TEXT NOT NULL,
  config_hash TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES connection_revisions (tenant_id, id)
);
CREATE INDEX check_runs_rev ON readiness_check_runs(tenant_id, revision_id, started_at);

CREATE TABLE readiness_item_states (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('required','recommended','optional')),
  status TEXT NOT NULL CHECK (status IN ('pending','pass','fail','blocked','stale','skipped','not_applicable')),
  source TEXT NOT NULL CHECK (source IN ('attestation','live','data','skip','system')),
  actor_id TEXT, note TEXT, review_by TEXT, check_run_id TEXT,
  config_hash TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id),
  CHECK (status <> 'skipped' OR (level = 'recommended' AND length(note) >= 20)),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES connection_revisions (tenant_id, id)
);
-- check_run_id is a reporting pointer, not a foreign key (item states are
-- recomputed from evidence and the run may be a simulated one without a row);
-- it keeps a cross-tenant guard trigger (tessera_guard_soft_ref, 0001).
CREATE TRIGGER tg_readiness_item_states_run_xtenant BEFORE INSERT OR UPDATE OF tenant_id, check_run_id ON readiness_item_states
  FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('readiness_check_runs', 'check_run_id', 'text');

CREATE TABLE readiness_attestations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  note TEXT NOT NULL CHECK (length(note) >= 10),
  item_hash TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  attested_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES connection_revisions (tenant_id, id)
);

CREATE TABLE readiness_skips (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level = 'recommended'),
  actor_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) >= 20),
  review_by TEXT NOT NULL,
  template_version TEXT NOT NULL,
  skipped_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES connection_revisions (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);

CREATE TABLE readiness_overlays (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connector_type TEXT NOT NULL, connection_id TEXT,
  version BIGINT NOT NULL, body TEXT NOT NULL,
  updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connector_type, connection_id, version),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);

CREATE TABLE readiness_check_results (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pass','fail','warn','error','skipped','blocked')),
  observed TEXT NOT NULL, message TEXT NOT NULL, duration_ms BIGINT NOT NULL,
  item_hash TEXT NOT NULL,
  simulated BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, run_id, item_id, check_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES readiness_check_runs (tenant_id, id)
);

CREATE TABLE recon_runs (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  revision_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('staging','live')),
  check_run_id TEXT NOT NULL, counts TEXT, status TEXT NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES connection_revisions (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id),
  FOREIGN KEY (tenant_id, check_run_id) REFERENCES readiness_check_runs (tenant_id, id)
);
CREATE INDEX recon_runs_rev ON recon_runs(tenant_id, revision_id, started_at);

CREATE TABLE recon_findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL,
  connection_id TEXT NOT NULL, code TEXT NOT NULL, variant TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  count BIGINT NOT NULL, denominator BIGINT NOT NULL,
  samples TEXT NOT NULL, impact TEXT NOT NULL, cause TEXT, item_id TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','resolved')),
  accepted_by TEXT, reason TEXT, expires_at TEXT,
  first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  CHECK (status <> 'accepted' OR length(reason) >= 20),
  FOREIGN KEY (tenant_id, run_id) REFERENCES recon_runs (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
CREATE INDEX recon_findings_conn ON recon_findings(tenant_id, connection_id, status, severity);
CREATE INDEX recon_findings_run ON recon_findings(tenant_id, run_id);

CREATE TABLE readiness_scores (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  scope TEXT NOT NULL CHECK (scope IN ('connection','tenant')),
  connection_id TEXT, revision_id TEXT,
  computed_at TEXT NOT NULL, score BIGINT NOT NULL CHECK (score BETWEEN 0 AND 100),
  band TEXT NOT NULL, breakdown TEXT NOT NULL,
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES connection_revisions (tenant_id, id)
);
CREATE INDEX readiness_scores_series ON readiness_scores(tenant_id, scope, connection_id, computed_at);
