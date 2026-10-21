-- Campaign configuration per review type (issue #298; owner-based types on the
-- ownership model of #167, the review templates of #166).
--
-- review_type_settings: one row per type the tenant configured (user_manager,
-- application_owner, entitlement_owner, role_owner, organization_owner,
-- service_account); a type with no row has the defaults in internal/reviews.
-- reviewer_source says who reviews: the object's primary owner ('owner'), the
-- primary owner or else the backup ('owner_or_backup'), or one named person
-- ('fixed', reviewer_identity_id). fallback_reviewer_id reviews what has no
-- reachable owner. on_incomplete is what happens to items nobody decided by the
-- due date: 'revoke' them, 'escalate' them to the fallback reviewer for
-- escalation_days and then revoke, or 'keep' the access and close the review
-- as incomplete. updated_by is the display name of the admin who saved it; the
-- audit ledger keeps the history.
--
-- review_template_types: the type a review template runs as. A template with
-- no row is the original all-purpose schedule.
--
-- Tenant-owned: guard triggers at the end refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS review_type_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  review_type TEXT NOT NULL CHECK (review_type IN ('user_manager','application_owner','entitlement_owner','role_owner','organization_owner','service_account')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  reviewer_source TEXT NOT NULL DEFAULT 'owner_or_backup' CHECK (reviewer_source IN ('owner','owner_or_backup','fixed')),
  reviewer_identity_id INTEGER REFERENCES identities (id),
  fallback_reviewer_id INTEGER REFERENCES identities (id),
  on_incomplete TEXT NOT NULL DEFAULT 'revoke' CHECK (on_incomplete IN ('revoke','escalate','keep')),
  escalation_days INTEGER NOT NULL DEFAULT 7 CHECK (escalation_days BETWEEN 1 AND 30),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, review_type),
  CHECK (reviewer_source <> 'fixed' OR reviewer_identity_id IS NOT NULL),
  CHECK (on_incomplete <> 'escalate' OR fallback_reviewer_id IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS review_template_types (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  template_id TEXT NOT NULL REFERENCES review_templates (id),
  review_type TEXT NOT NULL CHECK (review_type IN ('user_manager','application_owner','entitlement_owner','role_owner','organization_owner','service_account')),
  PRIMARY KEY (tenant_id, template_id)
);

CREATE TRIGGER IF NOT EXISTS tg_review_type_settings_xtenant_ins BEFORE INSERT ON review_type_settings
WHEN (NEW.reviewer_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.reviewer_identity_id AND i.tenant_id <> NEW.tenant_id))
	OR (NEW.fallback_reviewer_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.fallback_reviewer_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_type_settings'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_type_settings_xtenant_upd BEFORE UPDATE OF tenant_id, reviewer_identity_id, fallback_reviewer_id ON review_type_settings
WHEN (NEW.reviewer_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.reviewer_identity_id AND i.tenant_id <> NEW.tenant_id))
	OR (NEW.fallback_reviewer_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.fallback_reviewer_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_type_settings'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_template_types_xtenant_ins BEFORE INSERT ON review_template_types
WHEN EXISTS (SELECT 1 FROM review_templates t WHERE t.id = NEW.template_id AND t.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_template_types'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_template_types_xtenant_upd BEFORE UPDATE OF tenant_id, template_id ON review_template_types
WHEN EXISTS (SELECT 1 FROM review_templates t WHERE t.id = NEW.template_id AND t.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_template_types'); END;
