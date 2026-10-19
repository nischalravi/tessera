-- Access drift and its remediation policy (issue #301).
--
-- access_drift is one row per difference between intended and observed access
-- that the reconciliation engine (internal/reconcile) found. drift_key names
-- the difference (class plus what it is about), unique per tenant, so a rerun
-- updates the row instead of adding one, and a difference that comes back
-- reopens its row. Classes: missing (intended, not present), rogue (present,
-- never intended), orphan (the account has no identity), stale (the intent
-- ended, the access is still present). Status: open, remediating (an action
-- is under way), resolved (the difference is gone), accepted (a person
-- accepted the risk). intended_id and observed_id point at the two sides.
--
-- remediation_policies say what to do about a class of drift for one system
-- or one entitlement of it: auto_provision, auto_revoke, owner_task (a task in
-- the owner's Inbox) or report_only (the default: record it and stop).
CREATE TABLE IF NOT EXISTS access_drift (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  drift_key TEXT NOT NULL,
  class TEXT NOT NULL CHECK (class IN ('missing','rogue','orphan','stale')),
  system TEXT NOT NULL,
  entitlement_kind TEXT NOT NULL DEFAULT 'group',
  entitlement_ref TEXT NOT NULL DEFAULT '',
  account_ref TEXT NOT NULL DEFAULT '',
  account_id INTEGER REFERENCES accounts (id),
  identity_id INTEGER REFERENCES identities (id),
  intended_id TEXT REFERENCES intended_grants (id),
  observed_id INTEGER,
  owner_identity_id INTEGER REFERENCES identities (id),
  status TEXT NOT NULL CHECK (status IN ('open','remediating','resolved','accepted')),
  detected_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  resolved_at TEXT,
  accepted_by TEXT,
  accepted_reason TEXT,
  action TEXT NOT NULL DEFAULT 'none' CHECK (action IN ('none','auto_provision','auto_revoke','owner_task','report_only')),
  remediation_ref TEXT,
  remediation_note TEXT,
  remediation_at TEXT,
  UNIQUE (tenant_id, drift_key),
  UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS ix_access_drift_status ON access_drift (tenant_id, status, class);
CREATE INDEX IF NOT EXISTS ix_access_drift_system ON access_drift (tenant_id, system);

CREATE TABLE IF NOT EXISTS remediation_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  system TEXT NOT NULL,
  entitlement_ref TEXT NOT NULL DEFAULT '',
  drift_class TEXT NOT NULL CHECK (drift_class IN ('missing','rogue','orphan','stale')),
  action TEXT NOT NULL CHECK (action IN ('auto_provision','auto_revoke','owner_task','report_only')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, system, entitlement_ref, drift_class),
  UNIQUE (tenant_id, id)
);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_access_drift_xtenant_ins BEFORE INSERT ON access_drift
WHEN (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.intended_id IS NOT NULL AND EXISTS (SELECT 1 FROM intended_grants p WHERE p.id = NEW.intended_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_drift'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_drift_xtenant_upd BEFORE UPDATE OF tenant_id, account_id, identity_id, owner_identity_id, intended_id ON access_drift
WHEN (NEW.account_id IS NOT NULL AND EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.intended_id IS NOT NULL AND EXISTS (SELECT 1 FROM intended_grants p WHERE p.id = NEW.intended_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_drift'); END;
