-- Mitigating controls and remediation options for SoD violations (issue #298).
--
-- sod_controls: the control library. A control has an owner (an identity), a
-- type (preventive, detective, corrective), a frequency and the evidence it
-- needs. `version` counts saved changes; the audit ledger keeps the history.
--
-- sod_mitigations: one identity's violation of one risk (risk_id x identity_id)
-- covered for a while: either by a control (kind 'control') or accepted as is
-- (kind 'accept'). It is requested by one person and decided by another
-- (four-eyes, enforced by the server), has a mandatory end date, and ends by
-- expiring, being revoked early, or being rejected or cancelled before it
-- starts. At most one mitigation per risk and identity is pending or active.
-- `evidence` is a JSON list of references, `warned_at` is when the owner was
-- told it is ending.
--
-- sod_risk_options: the remediation options a risk offers (revoke, mitigate,
-- accept, escalate). A risk with no rows offers all four.
--
-- sod_escalations: a violation sent to the risk owner.
--
-- Tenant-owned: guard triggers at the end refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS sod_controls (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  owner_identity_id INTEGER REFERENCES identities (id),
  type TEXT NOT NULL CHECK (type IN ('preventive','detective','corrective')),
  frequency TEXT NOT NULL CHECK (frequency IN ('continuous','daily','weekly','monthly','quarterly','annually')),
  evidence_requirement TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS sod_mitigations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  risk_id TEXT NOT NULL REFERENCES sod_risks (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  kind TEXT NOT NULL CHECK (kind IN ('control','accept')),
  control_id TEXT REFERENCES sod_controls (id),
  justification TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL CHECK (status IN ('pending','active','rejected','cancelled','expired','revoked')),
  starts_at TEXT,
  ends_at TEXT NOT NULL,
  requested_by TEXT NOT NULL REFERENCES platform_users (id),
  requested_at TEXT NOT NULL,
  decided_by TEXT REFERENCES platform_users (id),
  decided_at TEXT,
  decision_note TEXT,
  revoked_by TEXT REFERENCES platform_users (id),
  revoke_reason TEXT,
  warned_at TEXT,
  closed_at TEXT,
  CHECK ((kind = 'control') = (control_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS ix_sod_mitigations_tenant_risk ON sod_mitigations (tenant_id, risk_id, identity_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sod_mitigations_live ON sod_mitigations (tenant_id, risk_id, identity_id)
  WHERE status IN ('pending','active');

CREATE TABLE IF NOT EXISTS sod_risk_options (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  risk_id TEXT NOT NULL REFERENCES sod_risks (id),
  remediation TEXT NOT NULL CHECK (remediation IN ('revoke','mitigate','accept','escalate')),
  PRIMARY KEY (tenant_id, risk_id, remediation)
);

CREATE TABLE IF NOT EXISTS sod_escalations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  risk_id TEXT NOT NULL REFERENCES sod_risks (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  escalated_by TEXT NOT NULL REFERENCES platform_users (id),
  note TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_sod_escalations_tenant_risk ON sod_escalations (tenant_id, risk_id, identity_id);

-- Cross-tenant reference guards (same pattern as 0300_sod.sql).

CREATE TRIGGER IF NOT EXISTS tg_sod_controls_xtenant_ins BEFORE INSERT ON sod_controls
WHEN (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.owner_identity_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_controls'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_controls_xtenant_upd BEFORE UPDATE OF tenant_id, updated_by, owner_identity_id ON sod_controls
WHEN (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.owner_identity_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_controls'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_mitigations_xtenant_ins BEFORE INSERT ON sod_mitigations
WHEN EXISTS (SELECT 1 FROM sod_risks r WHERE r.id = NEW.risk_id AND r.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.identity_id AND i.tenant_id <> NEW.tenant_id)
	OR (NEW.control_id IS NOT NULL AND EXISTS (SELECT 1 FROM sod_controls c WHERE c.id = NEW.control_id AND c.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.tenant_id <> NEW.tenant_id AND p.id IN (NEW.requested_by, COALESCE(NEW.decided_by, ''), COALESCE(NEW.revoked_by, '')))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_mitigations'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_mitigations_xtenant_upd BEFORE UPDATE OF tenant_id, risk_id, identity_id, control_id, requested_by, decided_by, revoked_by ON sod_mitigations
WHEN EXISTS (SELECT 1 FROM sod_risks r WHERE r.id = NEW.risk_id AND r.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.identity_id AND i.tenant_id <> NEW.tenant_id)
	OR (NEW.control_id IS NOT NULL AND EXISTS (SELECT 1 FROM sod_controls c WHERE c.id = NEW.control_id AND c.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.tenant_id <> NEW.tenant_id AND p.id IN (NEW.requested_by, COALESCE(NEW.decided_by, ''), COALESCE(NEW.revoked_by, '')))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_mitigations'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_risk_options_xtenant_ins BEFORE INSERT ON sod_risk_options
WHEN EXISTS (SELECT 1 FROM sod_risks r WHERE r.id = NEW.risk_id AND r.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_risk_options'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_risk_options_xtenant_upd BEFORE UPDATE OF tenant_id, risk_id ON sod_risk_options
WHEN EXISTS (SELECT 1 FROM sod_risks r WHERE r.id = NEW.risk_id AND r.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_risk_options'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_escalations_xtenant_ins BEFORE INSERT ON sod_escalations
WHEN EXISTS (SELECT 1 FROM sod_risks r WHERE r.id = NEW.risk_id AND r.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.identity_id AND i.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.escalated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_escalations'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_escalations_xtenant_upd BEFORE UPDATE OF tenant_id, risk_id, identity_id, escalated_by ON sod_escalations
WHEN EXISTS (SELECT 1 FROM sod_risks r WHERE r.id = NEW.risk_id AND r.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.identity_id AND i.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.escalated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_escalations'); END;
