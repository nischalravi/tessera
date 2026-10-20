-- Intended and observed access, stored separately (issue #301).
--
-- intended_grants is what Tessera decided someone should have: one row per
-- identity and target entitlement, with its provenance (an approved request
-- line, a business role or birthright rule, a JIT approval, a review "keep",
-- a manual admin grant), a validity window and an owner. Revocation or expiry
-- closes the row (closed_at, close_reason); it is never deleted, so a later
-- "present but the intent ended" is recognised as stale. Only approval-side
-- code writes it (store/repo_access_model.go is the one place).
--
-- observed_runs and observed_entitlements are what a system actually reports:
-- one run per connector sync and system, one row per account and entitlement
-- it showed, with the run id and time. Only connector ingest writes them. A
-- row carries the identity link when the account had one; the reconciliation
-- engine (internal/reconcile) re-reads the account's current link.
--
-- grant_edges stays the live model that the graph, insights, SoD and reviews
-- read; both tables are written beside it, in the same transaction.
CREATE TABLE IF NOT EXISTS intended_grants (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  account_id INTEGER REFERENCES accounts (id),
  target_kind TEXT NOT NULL CHECK (target_kind IN ('group','perm')),
  target_system TEXT NOT NULL,
  target_ref TEXT NOT NULL,
  provenance TEXT NOT NULL CHECK (provenance IN ('request','role','birthright','jit','review_keep','manual')),
  provenance_ref TEXT,
  edge_id INTEGER,
  valid_from TEXT NOT NULL,
  valid_until TEXT,
  owner_identity_id INTEGER REFERENCES identities (id),
  created_at TEXT NOT NULL,
  closed_at TEXT,
  close_reason TEXT,
  CHECK ((closed_at IS NULL) = (close_reason IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_intended_grants_open ON intended_grants (tenant_id, identity_id, target_kind, target_system, target_ref) WHERE closed_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_intended_grants_edge ON intended_grants (tenant_id, edge_id);
CREATE INDEX IF NOT EXISTS ix_intended_grants_target ON intended_grants (tenant_id, target_system, target_ref);

CREATE TABLE IF NOT EXISTS observed_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('connector','backfill')),
  observed_at TEXT NOT NULL,
  entitlements INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS ix_observed_runs_system ON observed_runs (tenant_id, system, observed_at);

CREATE TABLE IF NOT EXISTS observed_entitlements (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  account_ref TEXT NOT NULL,
  account_id INTEGER REFERENCES accounts (id),
  identity_id INTEGER REFERENCES identities (id),
  entitlement_kind TEXT NOT NULL CHECK (entitlement_kind IN ('group','perm')),
  entitlement_system TEXT NOT NULL,
  entitlement_ref TEXT NOT NULL,
  run_id TEXT NOT NULL REFERENCES observed_runs (id),
  observed_at TEXT NOT NULL,
  UNIQUE (tenant_id, system, account_ref, entitlement_kind, entitlement_system, entitlement_ref)
);
CREATE INDEX IF NOT EXISTS ix_observed_entitlements_run ON observed_entitlements (tenant_id, system, run_id);
CREATE INDEX IF NOT EXISTS ix_observed_entitlements_ent ON observed_entitlements (tenant_id, entitlement_system, entitlement_ref);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_intended_grants_xtenant_ins BEFORE INSERT ON intended_grants
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: intended_grants'); END;

CREATE TRIGGER IF NOT EXISTS tg_intended_grants_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, account_id, owner_identity_id ON intended_grants
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: intended_grants'); END;

CREATE TRIGGER IF NOT EXISTS tg_observed_entitlements_xtenant_ins BEFORE INSERT ON observed_entitlements
WHEN (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM observed_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: observed_entitlements'); END;

CREATE TRIGGER IF NOT EXISTS tg_observed_entitlements_xtenant_upd BEFORE UPDATE OF tenant_id, account_id, identity_id, run_id ON observed_entitlements
WHEN (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM observed_runs p WHERE p.id = NEW.run_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: observed_entitlements'); END;
