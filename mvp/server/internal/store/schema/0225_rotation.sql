-- Secret rotation orchestration (issue #113). Tenant-owned like every table
-- of 0001_tenancy.sql: tenant_id references tenants(id), every UNIQUE
-- constraint starts with tenant_id and the guard triggers at the end refuse a
-- reference to another tenant's row.
--
-- Tessera does not store the secrets it rotates. The only credential
-- material here is the rotation adapters' own (an AWS access key, a Vault
-- token, a GitHub token), sealed under the KEK with internal/seal and bound
-- by AAD to tenant, table, column and row. A new credential is written to
-- the customer's vault and is never persisted by Tessera.

-- Connection details and the sealed credential of one rotation adapter.
-- config holds only non-secret settings (region, endpoint, address, mount).
CREATE TABLE IF NOT EXISTS rotation_adapters (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('aws_iam','aws_secretsmanager','vault','github','fake')),
  config TEXT NOT NULL,
  secret_enc BLOB NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS rotation_adapters_tenant ON rotation_adapters(tenant_id);

-- Max age, grace period and adapter per secret kind (and optionally system).
-- system = '' applies to every system. adapter_id NULL means the policy only
-- tracks age and notifies the owner (manual rotation).
CREATE TABLE IF NOT EXISTS rotation_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL,
  system TEXT NOT NULL DEFAULT '',
  max_age_days INTEGER NOT NULL CHECK (max_age_days BETWEEN 1 AND 3650),
  grace_hours INTEGER NOT NULL CHECK (grace_hours BETWEEN 0 AND 720),
  adapter_id TEXT REFERENCES rotation_adapters (id),
  dest_adapter_id TEXT REFERENCES rotation_adapters (id),
  dest_path TEXT NOT NULL DEFAULT '',
  auto_rotate INTEGER NOT NULL DEFAULT 0 CHECK (auto_rotate IN (0,1)),
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, kind, system)
);
CREATE INDEX IF NOT EXISTS rotation_policies_tenant ON rotation_policies(tenant_id);

-- One bulk "vendor compromised" run: the plan that was shown and confirmed.
-- plan holds ids, names and actions, never secret material.
CREATE TABLE IF NOT EXISTS rotation_bulks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) >= 10),
  plan TEXT NOT NULL,
  plan_hash TEXT NOT NULL,
  requested_by TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS rotation_bulks_tenant ON rotation_bulks(tenant_id, created_at);

-- A rotation job: created -> handed_over -> old_disabled -> verified ->
-- old_deleted, or failed. 'pending' is the queue state before the new
-- credential exists; 'cancelled' is an operator cancelling a pending job.
-- The CHECK makes "verified by re-read" structural: a job cannot reach
-- verified or old_deleted without the recorded observation of the old
-- credential's age and last use.
CREATE TABLE IF NOT EXISTS rotation_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  secret_id INTEGER NOT NULL REFERENCES secrets (id),
  bulk_id TEXT REFERENCES rotation_bulks (id),
  origin TEXT NOT NULL CHECK (origin IN ('manual','policy','vendor_compromise','jml')),
  adapter_id TEXT NOT NULL REFERENCES rotation_adapters (id),
  adapter_type TEXT NOT NULL,
  dest_adapter_id TEXT REFERENCES rotation_adapters (id),
  dest_path TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL CHECK (state IN ('pending','created','handed_over','old_disabled','verified','old_deleted','failed','cancelled')),
  failed_state TEXT,
  old_ref TEXT NOT NULL,
  new_ref TEXT,
  grace_hours INTEGER NOT NULL CHECK (grace_hours BETWEEN 0 AND 720),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  next_step_at TEXT NOT NULL,
  lease_until TEXT,
  handed_over_at TEXT, disabled_at TEXT, verified_at TEXT, completed_at TEXT,
  verification TEXT,
  requested_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  CHECK (state NOT IN ('verified','old_deleted') OR verification IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS rotation_jobs_tenant ON rotation_jobs(tenant_id, state, next_step_at);
CREATE INDEX IF NOT EXISTS rotation_jobs_secret ON rotation_jobs(tenant_id, secret_id);
-- at most one job in flight per secret
CREATE UNIQUE INDEX IF NOT EXISTS rotation_jobs_one_active ON rotation_jobs(tenant_id, secret_id)
  WHERE state NOT IN ('old_deleted','failed','cancelled');

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_rotation_policies_xtenant_ins BEFORE INSERT ON rotation_policies
WHEN (NEW.adapter_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_adapters p WHERE p.id = NEW.adapter_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.dest_adapter_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_adapters p WHERE p.id = NEW.dest_adapter_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: rotation_policies'); END;

CREATE TRIGGER IF NOT EXISTS tg_rotation_policies_xtenant_upd BEFORE UPDATE OF tenant_id, adapter_id, dest_adapter_id ON rotation_policies
WHEN (NEW.adapter_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_adapters p WHERE p.id = NEW.adapter_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.dest_adapter_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_adapters p WHERE p.id = NEW.dest_adapter_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: rotation_policies'); END;

CREATE TRIGGER IF NOT EXISTS tg_rotation_jobs_xtenant_ins BEFORE INSERT ON rotation_jobs
WHEN (NEW.secret_id IS NOT NULL AND EXISTS (SELECT 1 FROM secrets p WHERE p.id = NEW.secret_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.bulk_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_bulks p WHERE p.id = NEW.bulk_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.adapter_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_adapters p WHERE p.id = NEW.adapter_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.dest_adapter_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_adapters p WHERE p.id = NEW.dest_adapter_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: rotation_jobs'); END;

CREATE TRIGGER IF NOT EXISTS tg_rotation_jobs_xtenant_upd BEFORE UPDATE OF tenant_id, secret_id, bulk_id, adapter_id, dest_adapter_id ON rotation_jobs
WHEN (NEW.secret_id IS NOT NULL AND EXISTS (SELECT 1 FROM secrets p WHERE p.id = NEW.secret_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.bulk_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_bulks p WHERE p.id = NEW.bulk_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.adapter_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_adapters p WHERE p.id = NEW.adapter_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.dest_adapter_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_adapters p WHERE p.id = NEW.dest_adapter_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: rotation_jobs'); END;
