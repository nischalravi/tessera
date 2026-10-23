-- Recently added authentication methods and the verified help-desk reset
-- (issue #477). MFA bypass by vishing the help desk continues (ShinyHunters
-- against Okta SSO) and Entra has a real-time detection for suspiciously added
-- authentication methods, so a reset for an identity that gained a method in
-- the last N days needs a second approver, or is blocked.
--
-- helpdesk_settings: one row per tenant (no row means the defaults: 7 days,
-- require_approval). recent_method_action is off, require_approval (the case
-- needs the second approver a privileged identity needs) or block (the case
-- cannot execute while the window is open).
--
-- helpdesk_idp_risks: a risk signal a connected IdP reported for an identity
-- (kind auth_method_added: Entra's "suspicious authentication method added"
-- detection or an Okta equivalent), fed by POST /api/helpdesk/risk-signals
-- until the IdP log connectors feed it. detail is a short description; no
-- secret or factor value is held.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's identity.
CREATE TABLE IF NOT EXISTS helpdesk_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  recent_method_days INTEGER NOT NULL DEFAULT 7 CHECK (recent_method_days BETWEEN 1 AND 90),
  recent_method_action TEXT NOT NULL DEFAULT 'require_approval' CHECK (recent_method_action IN ('off','require_approval','block')),
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS helpdesk_idp_risks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  kind TEXT NOT NULL CHECK (kind IN ('auth_method_added')),
  source TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  occurred_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_helpdesk_idp_risks_identity ON helpdesk_idp_risks (tenant_id, identity_id, occurred_at);

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_idp_risks_xtenant_ins BEFORE INSERT ON helpdesk_idp_risks
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_idp_risks'); END;

CREATE TRIGGER IF NOT EXISTS tg_helpdesk_idp_risks_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON helpdesk_idp_risks
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: helpdesk_idp_risks'); END;
