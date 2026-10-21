-- Postgres dialect of schema/0491_review_types.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id).

-- +goose Up

CREATE TABLE review_type_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  review_type TEXT NOT NULL CHECK (review_type IN ('user_manager','application_owner','entitlement_owner','role_owner','organization_owner','service_account')),
  enabled BIGINT NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  reviewer_source TEXT NOT NULL DEFAULT 'owner_or_backup' CHECK (reviewer_source IN ('owner','owner_or_backup','fixed')),
  reviewer_identity_id BIGINT,
  fallback_reviewer_id BIGINT,
  on_incomplete TEXT NOT NULL DEFAULT 'revoke' CHECK (on_incomplete IN ('revoke','escalate','keep')),
  escalation_days BIGINT NOT NULL DEFAULT 7 CHECK (escalation_days BETWEEN 1 AND 30),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, review_type),
  CHECK (reviewer_source <> 'fixed' OR reviewer_identity_id IS NOT NULL),
  CHECK (on_incomplete <> 'escalate' OR fallback_reviewer_id IS NOT NULL),
  FOREIGN KEY (tenant_id, reviewer_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, fallback_reviewer_id) REFERENCES identities (tenant_id, id)
);

CREATE TABLE review_template_types (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  template_id TEXT NOT NULL,
  review_type TEXT NOT NULL CHECK (review_type IN ('user_manager','application_owner','entitlement_owner','role_owner','organization_owner','service_account')),
  PRIMARY KEY (tenant_id, template_id),
  FOREIGN KEY (tenant_id, template_id) REFERENCES review_templates (tenant_id, id)
);
