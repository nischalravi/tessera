-- Business roles (issue #161): a role bundles entitlements (groups) across
-- connections, with an owner, a description, a risk and an optional
-- birthright rule.
--
-- business_roles: status active or retired; birthright is NULL (no rule) or
-- a JSON object of attribute lists ({"department": [...], "type": [...],
-- "title": [...]}); an identity matches when it is active and, for every
-- non-empty list, its attribute is in the list. version counts the saved
-- changes; each one is a row of business_role_versions.
--
-- business_role_entitlements: the groups a role grants.
--
-- business_role_versions: append-only snapshots of each saved change (the
-- role and its entitlements as JSON), with who made it and why.
--
-- business_role_members: who holds a role and how it was assigned (rule,
-- request or manual). Holding a role grants its entitlements as grant edges
-- with source 'role' from the member's account; an edge granted another way
-- (connector, request, manual) is left alone, and a 'role' edge is removed
-- only when none of the person's roles still grants the group.
--
-- business_role_requests: requests for a role through the catalog
-- (pending, approved, denied, cancelled); approval assigns the role.
--
-- Tenant-owned: guard triggers at the end refuse references to another
-- tenant's rows.
CREATE TABLE IF NOT EXISTS business_roles (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  owner_identity_id INTEGER REFERENCES identities (id),
  risk TEXT NOT NULL DEFAULT 'low' CHECK (risk IN ('low','medium','high')),
  requestable INTEGER NOT NULL DEFAULT 0,
  birthright TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS business_role_entitlements (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  role_id TEXT NOT NULL REFERENCES business_roles (id),
  group_id INTEGER NOT NULL REFERENCES groups (id),
  UNIQUE (tenant_id, role_id, group_id)
);
CREATE INDEX IF NOT EXISTS ix_role_entitlements_tenant_group ON business_role_entitlements (tenant_id, group_id);

CREATE TABLE IF NOT EXISTS business_role_versions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  role_id TEXT NOT NULL REFERENCES business_roles (id),
  version INTEGER NOT NULL,
  snapshot TEXT NOT NULL,
  note TEXT,
  changed_by TEXT REFERENCES platform_users (id),
  actor TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  UNIQUE (tenant_id, role_id, version)
);

CREATE TRIGGER IF NOT EXISTS tg_business_role_versions_no_update BEFORE UPDATE ON business_role_versions
BEGIN SELECT RAISE(ABORT, 'business_role_versions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_business_role_versions_no_delete BEFORE DELETE ON business_role_versions
BEGIN SELECT RAISE(ABORT, 'business_role_versions is append-only'); END;

CREATE TABLE IF NOT EXISTS business_role_members (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  role_id TEXT NOT NULL REFERENCES business_roles (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  source TEXT NOT NULL CHECK (source IN ('rule','request','manual')),
  assigned_by TEXT REFERENCES platform_users (id),
  assigned_at TEXT NOT NULL,
  request_id TEXT,
  UNIQUE (tenant_id, role_id, identity_id)
);
CREATE INDEX IF NOT EXISTS ix_role_members_tenant_identity ON business_role_members (tenant_id, identity_id);

CREATE TABLE IF NOT EXISTS business_role_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  role_id TEXT NOT NULL REFERENCES business_roles (id),
  beneficiary_id INTEGER NOT NULL REFERENCES identities (id),
  requested_by TEXT NOT NULL REFERENCES platform_users (id),
  justification TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','cancelled')),
  requested_at TEXT NOT NULL,
  decided_by TEXT REFERENCES platform_users (id),
  decided_at TEXT,
  decision_reason TEXT
);
CREATE INDEX IF NOT EXISTS ix_role_requests_tenant_status ON business_role_requests (tenant_id, status);
-- one pending request per person and role
CREATE UNIQUE INDEX IF NOT EXISTS ux_role_requests_pending ON business_role_requests (tenant_id, role_id, beneficiary_id)
  WHERE status = 'pending';

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_business_roles_xtenant_ins BEFORE INSERT ON business_roles
WHEN (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_roles'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_roles_xtenant_upd BEFORE UPDATE OF tenant_id, owner_identity_id, updated_by ON business_roles
WHEN (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_roles'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_entitlements_xtenant_ins BEFORE INSERT ON business_role_entitlements
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_entitlements'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_entitlements_xtenant_upd BEFORE UPDATE OF tenant_id, role_id, group_id ON business_role_entitlements
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_entitlements'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_versions_xtenant_ins BEFORE INSERT ON business_role_versions
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.changed_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.changed_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_versions_xtenant_upd BEFORE UPDATE OF tenant_id, role_id, changed_by ON business_role_versions
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.changed_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.changed_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_members_xtenant_ins BEFORE INSERT ON business_role_members
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.assigned_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.assigned_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.request_id IS NOT NULL AND EXISTS (SELECT 1 FROM business_role_requests p WHERE p.id = NEW.request_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_members'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_members_xtenant_upd BEFORE UPDATE OF tenant_id, role_id, identity_id, assigned_by, request_id ON business_role_members
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.assigned_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.assigned_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.request_id IS NOT NULL AND EXISTS (SELECT 1 FROM business_role_requests p WHERE p.id = NEW.request_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_members'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_requests_xtenant_ins BEFORE INSERT ON business_role_requests
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.beneficiary_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_business_role_requests_xtenant_upd BEFORE UPDATE OF tenant_id, role_id, beneficiary_id, requested_by, decided_by ON business_role_requests
WHEN EXISTS (SELECT 1 FROM business_roles p WHERE p.id = NEW.role_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.beneficiary_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: business_role_requests'); END;
