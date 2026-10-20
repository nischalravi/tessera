-- Postgres dialect of schema/0225_rotation.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE rotation_adapters (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('aws_iam','aws_secretsmanager','vault','github','fake')),
  config TEXT NOT NULL,
  secret_enc BYTEA NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id)
);
CREATE INDEX rotation_adapters_tenant ON rotation_adapters(tenant_id);

-- Max age, grace period and adapter per secret kind (and optionally system).
-- system = '' applies to every system. adapter_id NULL means the policy only
-- tracks age and notifies the owner (manual rotation).
CREATE TABLE rotation_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL,
  system TEXT NOT NULL DEFAULT '',
  max_age_days BIGINT NOT NULL CHECK (max_age_days BETWEEN 1 AND 3650),
  grace_hours BIGINT NOT NULL CHECK (grace_hours BETWEEN 0 AND 720),
  adapter_id TEXT,
  dest_adapter_id TEXT,
  dest_path TEXT NOT NULL DEFAULT '',
  auto_rotate BIGINT NOT NULL DEFAULT 0 CHECK (auto_rotate IN (0,1)),
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, kind, system),
  FOREIGN KEY (tenant_id, adapter_id) REFERENCES rotation_adapters (tenant_id, id),
  FOREIGN KEY (tenant_id, dest_adapter_id) REFERENCES rotation_adapters (tenant_id, id)
);
CREATE INDEX rotation_policies_tenant ON rotation_policies(tenant_id);

-- One bulk "vendor compromised" run: the plan that was shown and confirmed.
-- plan holds ids, names and actions, never secret material.
CREATE TABLE rotation_bulks (
  id TEXT PRIMARY KEY,
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) >= 10),
  plan TEXT NOT NULL,
  plan_hash TEXT NOT NULL,
  requested_by TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE (tenant_id, id)
);
CREATE INDEX rotation_bulks_tenant ON rotation_bulks(tenant_id, created_at);

-- A rotation job: created -> handed_over -> old_disabled -> verified ->
-- old_deleted, or failed. 'pending' is the queue state before the new
-- credential exists; 'cancelled' is an operator cancelling a pending job.
-- The CHECK makes "verified by re-read" structural: a job cannot reach
-- verified or old_deleted without the recorded observation of the old
-- credential's age and last use.
CREATE TABLE rotation_jobs (
  id TEXT PRIMARY KEY,
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  secret_id BIGINT NOT NULL,
  bulk_id TEXT,
  origin TEXT NOT NULL CHECK (origin IN ('manual','policy','vendor_compromise','jml')),
  adapter_id TEXT NOT NULL,
  adapter_type TEXT NOT NULL,
  dest_adapter_id TEXT,
  dest_path TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL CHECK (state IN ('pending','created','handed_over','old_disabled','verified','old_deleted','failed','cancelled')),
  failed_state TEXT,
  old_ref TEXT NOT NULL,
  new_ref TEXT,
  grace_hours BIGINT NOT NULL CHECK (grace_hours BETWEEN 0 AND 720),
  attempts BIGINT NOT NULL DEFAULT 0,
  last_error TEXT,
  next_step_at TEXT NOT NULL,
  lease_until TEXT,
  handed_over_at TEXT, disabled_at TEXT, verified_at TEXT, completed_at TEXT,
  verification TEXT,
  requested_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  CHECK (state NOT IN ('verified','old_deleted') OR verification IS NOT NULL),
  FOREIGN KEY (tenant_id, secret_id) REFERENCES secrets (tenant_id, id),
  FOREIGN KEY (tenant_id, bulk_id) REFERENCES rotation_bulks (tenant_id, id),
  FOREIGN KEY (tenant_id, adapter_id) REFERENCES rotation_adapters (tenant_id, id),
  FOREIGN KEY (tenant_id, dest_adapter_id) REFERENCES rotation_adapters (tenant_id, id)
);
CREATE INDEX rotation_jobs_tenant ON rotation_jobs(tenant_id, state, next_step_at);
CREATE INDEX rotation_jobs_secret ON rotation_jobs(tenant_id, secret_id);
-- at most one job in flight per secret
CREATE UNIQUE INDEX rotation_jobs_one_active ON rotation_jobs(tenant_id, secret_id)
  WHERE state NOT IN ('old_deleted','failed','cancelled');

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).
