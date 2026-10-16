-- Access reviews certify business-role memberships (issue #214).
--
-- business_role_exclusions: people a birthright rule must not assign, with
-- why and who decided. The list is versioned per role: every add or removal
-- takes the next version (version for an add, removed_version for a
-- removal), and rows are never deleted, so the history stays. An exclusion
-- is active while removed_at IS NULL; birthright evaluation skips an active
-- exclusion. review_item_id links the review decision that made it.
--
-- review_item_roles: marks a review item as a role membership (the item's
-- edge_src is "role:<id>" and edge_dst "identity:<id>") and records how the
-- reviewer resolved it: unassign (a manual or request membership removed),
-- exclude (a rule member excluded) or flag (the rule flagged to the role
-- owner). member_source is the membership's source when the campaign was
-- generated.
--
-- review_template_roles: the roles a review schedule is scoped to. A
-- template with rows reviews the memberships of those roles only.
--
-- Tenant-owned: guard triggers at the end refuse references to another
-- tenant's rows.
CREATE TABLE IF NOT EXISTS business_role_exclusions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  role_id TEXT NOT NULL REFERENCES business_roles (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  reason TEXT NOT NULL,
  version INTEGER NOT NULL,
  excluded_by TEXT REFERENCES platform_users (id),
  excluded_actor TEXT NOT NULL,
  excluded_at TEXT NOT NULL,
  review_item_id INTEGER REFERENCES review_items (id),
  removed_at TEXT,
  removed_version INTEGER,
  removed_by TEXT REFERENCES platform_users (id),
  removed_reason TEXT,
  UNIQUE (tenant_id, role_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_role_exclusions_active ON business_role_exclusions (tenant_id, role_id, identity_id)
  WHERE removed_at IS NULL;

CREATE TABLE IF NOT EXISTS review_item_roles (
  item_id INTEGER PRIMARY KEY REFERENCES review_items (id),
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  role_id TEXT NOT NULL REFERENCES business_roles (id),
  member_source TEXT NOT NULL CHECK (member_source IN ('rule','request','manual')),
  resolution TEXT CHECK (resolution IN ('unassign','exclude','flag')),
  resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_review_item_roles_tenant_role ON review_item_roles (tenant_id, role_id);

CREATE TABLE IF NOT EXISTS review_template_roles (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  template_id TEXT NOT NULL REFERENCES review_templates (id),
  role_id TEXT NOT NULL REFERENCES business_roles (id),
  UNIQUE (tenant_id, template_id, role_id)
);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_business_role_exclusions_xtenant_ins BEFORE INSERT ON business_role_exclusions
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.excluded_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.excluded_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.removed_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.removed_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.review_item_id IS NOT NULL AND EXISTS (SELECT 1 FROM review_items p WHERE p.id = NEW.review_item_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_exclusions'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_exclusions_xtenant_upd BEFORE UPDATE OF tenant_id, role_id, identity_id, excluded_by, removed_by, review_item_id ON business_role_exclusions
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.excluded_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.excluded_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.removed_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.removed_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.review_item_id IS NOT NULL AND EXISTS (SELECT 1 FROM review_items p WHERE p.id = NEW.review_item_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_exclusions'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_exclusions_no_delete BEFORE DELETE ON business_role_exclusions
BEGIN SELECT RAISE(ABORT, 'business_role_exclusions is append-only'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_item_roles_xtenant_ins BEFORE INSERT ON review_item_roles
WHEN EXISTS (SELECT 1 FROM review_items p WHERE p.id = NEW.item_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_item_roles'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_item_roles_xtenant_upd BEFORE UPDATE OF tenant_id, item_id, role_id ON review_item_roles
WHEN EXISTS (SELECT 1 FROM review_items p WHERE p.id = NEW.item_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_item_roles'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_template_roles_xtenant_ins BEFORE INSERT ON review_template_roles
WHEN EXISTS (SELECT 1 FROM review_templates p WHERE p.id = NEW.template_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_template_roles'); END;

CREATE TRIGGER IF NOT EXISTS tg_review_template_roles_xtenant_upd BEFORE UPDATE OF tenant_id, template_id, role_id ON review_template_roles
WHEN EXISTS (SELECT 1 FROM review_templates p WHERE p.id = NEW.template_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: review_template_roles'); END;
