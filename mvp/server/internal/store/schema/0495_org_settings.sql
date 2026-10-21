-- Organization settings (issue #298, "Organization settings"). The organization
-- tree itself is derived from the HR data (internal/orgs); these tables hold what
-- administrators add to it.
--
-- org_owners: the people assigned as owners of an organization. An organization
-- with rows here lists them (active people only) instead of the owners derived
-- from the reporting lines. org_id is the derived id (root, dept-none or
-- dept-<hash>); ord orders the owners.
--
-- org_settings: an organization's policies. default_stages is a JSON list of
-- approval stages ('manager' | 'owner' | 'decider') used for a request line whose
-- catalog item has no approval policy of its own, when the beneficiary is in the
-- organization (default_escalate_hours is that policy's escalation); NULL means
-- no default. The ov_* columns override the tenant's request settings for
-- beneficiaries in the organization and can only tighten them: a justification
-- that is required, a longer minimum length, a shorter default or maximum
-- duration; NULL means no override.
--
-- org_hierarchy_source: where the hierarchy comes from. One row per tenant; no row
-- means the HR department of every ingested person. source is 'hr_department';
-- system, when set, limits the hierarchy to people ingested from that source.
-- updated_by is the display name of the admin who saved it; the audit ledger
-- keeps the history.
--
-- Tenant-owned: guard triggers at the end refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS org_owners (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  org_id TEXT NOT NULL,
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  ord INTEGER NOT NULL CHECK (ord >= 0),
  PRIMARY KEY (tenant_id, org_id, identity_id)
);

CREATE TABLE IF NOT EXISTS org_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  org_id TEXT NOT NULL,
  default_stages TEXT CHECK (default_stages IS NULL OR json_valid(default_stages)),
  default_escalate_hours REAL CHECK (default_escalate_hours IS NULL OR default_escalate_hours > 0),
  ov_justification_required INTEGER CHECK (ov_justification_required IS NULL OR ov_justification_required IN (0, 1)),
  ov_justification_min_length INTEGER CHECK (ov_justification_min_length IS NULL OR ov_justification_min_length BETWEEN 1 AND 1000),
  ov_default_hours REAL CHECK (ov_default_hours IS NULL OR ov_default_hours > 0),
  ov_max_hours REAL CHECK (ov_max_hours IS NULL OR ov_max_hours > 0),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, org_id)
);

CREATE TABLE IF NOT EXISTS org_hierarchy_source (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  source TEXT NOT NULL DEFAULT 'hr_department' CHECK (source IN ('hr_department')),
  system TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS tg_org_owners_xtenant_ins BEFORE INSERT ON org_owners
WHEN EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.identity_id AND i.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: org_owners'); END;

CREATE TRIGGER IF NOT EXISTS tg_org_owners_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON org_owners
WHEN EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.identity_id AND i.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: org_owners'); END;
