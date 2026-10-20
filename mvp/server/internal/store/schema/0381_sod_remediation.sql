-- Ruleset-level remediation options for SoD violations (issue #298; builds on
-- 0301_sod_controls.sql). A risk with its own rows in sod_risk_options uses them;
-- otherwise it inherits the options of its ruleset's row here; with neither it
-- offers all four (revoke, mitigate, accept, escalate).
--
-- options is a JSON list of the offered remediations ([] = all four).
-- escalate_to_identity_id is the approver an escalation of this ruleset's risks
-- goes to; NULL sends it to the risk owner. updated_by is the display name of the
-- admin who saved it; the audit ledger keeps the history.
--
-- Tenant-owned: guard triggers at the end refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS sod_ruleset_remediation (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  ruleset_id TEXT NOT NULL REFERENCES sod_rulesets (id),
  options TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(options)),
  escalate_to_identity_id INTEGER REFERENCES identities (id),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, ruleset_id)
);

CREATE TRIGGER IF NOT EXISTS tg_sod_ruleset_remediation_xtenant_ins BEFORE INSERT ON sod_ruleset_remediation
WHEN EXISTS (SELECT 1 FROM sod_rulesets r WHERE r.id = NEW.ruleset_id AND r.tenant_id <> NEW.tenant_id)
	OR (NEW.escalate_to_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.escalate_to_identity_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_ruleset_remediation'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_ruleset_remediation_xtenant_upd BEFORE UPDATE OF tenant_id, ruleset_id, escalate_to_identity_id ON sod_ruleset_remediation
WHEN EXISTS (SELECT 1 FROM sod_rulesets r WHERE r.id = NEW.ruleset_id AND r.tenant_id <> NEW.tenant_id)
	OR (NEW.escalate_to_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.escalate_to_identity_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_ruleset_remediation'); END;
