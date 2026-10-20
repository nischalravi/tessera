-- Role mining (issue #298): business roles suggested from the access people hold.
--
-- role_mining_runs: one row per run. params is the normalized settings JSON
-- and snapshot_hash the SHA-256 over the algorithm, the parameters and the
-- filtered input, so the same hash and parameters reproduce the candidates.
-- status: queued (waiting for the queue worker), running, succeeded, failed.
-- A large tenant's run is queued as a job (kind role_mining); a small one is
-- computed in the request.
--
-- role_mining_candidates: the suggestions of a run, ranked. entitlements,
-- members and outliers are JSON (group ids, identity ids, and
-- [{identity_id, extra}]); rule is the suggested birthright rule JSON.
-- status: open, accepted (role_id is the draft role it created) or dismissed
-- (decision_reason says why). similar_role_id is the most similar active
-- role at run time, similarity its Jaccard percent.
--
-- Tenant-owned: guard triggers at the end refuse references to another
-- tenant's rows.
CREATE TABLE IF NOT EXISTS role_mining_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  status TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
  params TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL DEFAULT '',
  people INTEGER NOT NULL DEFAULT 0,
  entitlements INTEGER NOT NULL DEFAULT 0,
  candidates INTEGER NOT NULL DEFAULT 0,
  skipped_existing INTEGER NOT NULL DEFAULT 0,
  truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0,1)),
  error TEXT NOT NULL DEFAULT '',
  requested_by TEXT REFERENCES platform_users (id),
  requested_actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_role_mining_runs_tenant ON role_mining_runs (tenant_id, created_at);

CREATE TABLE IF NOT EXISTS role_mining_candidates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL REFERENCES role_mining_runs (id),
  rank_no INTEGER NOT NULL,
  name TEXT NOT NULL,
  entitlements TEXT NOT NULL,
  members TEXT NOT NULL,
  outliers TEXT NOT NULL,
  coverage INTEGER NOT NULL,
  rule TEXT,
  confidence INTEGER NOT NULL,
  cohesion INTEGER NOT NULL,
  similar_role_id TEXT REFERENCES business_roles (id),
  similarity INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','dismissed')),
  decided_by TEXT REFERENCES platform_users (id),
  decided_actor TEXT,
  decided_at TEXT,
  decision_reason TEXT,
  role_id TEXT REFERENCES business_roles (id),
  UNIQUE (tenant_id, run_id, rank_no)
);
CREATE INDEX IF NOT EXISTS ix_role_mining_candidates_run ON role_mining_candidates (tenant_id, run_id);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_role_mining_runs_xtenant_ins BEFORE INSERT ON role_mining_runs
WHEN NEW.requested_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: role_mining_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_role_mining_runs_xtenant_upd BEFORE UPDATE OF tenant_id, requested_by ON role_mining_runs
WHEN NEW.requested_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: role_mining_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_role_mining_candidates_xtenant_ins BEFORE INSERT ON role_mining_candidates
WHEN EXISTS (SELECT 1 FROM role_mining_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.similar_role_id IS NOT NULL AND EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.similar_role_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.role_id IS NOT NULL AND EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: role_mining_candidates'); END;

CREATE TRIGGER IF NOT EXISTS tg_role_mining_candidates_xtenant_upd BEFORE UPDATE OF tenant_id, run_id, similar_role_id, decided_by, role_id ON role_mining_candidates
WHEN EXISTS (SELECT 1 FROM role_mining_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.similar_role_id IS NOT NULL AND EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.similar_role_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.role_id IS NOT NULL AND EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: role_mining_candidates'); END;
