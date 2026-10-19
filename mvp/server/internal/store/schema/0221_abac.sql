-- Attribute conditions (issue #162): named, versioned ABAC policies that
-- birthright rules and catalog eligibility point at.
--
-- abac_policies: a name, a description and a condition (the JSON of
-- internal/abac, canonical form). status is active or retired; version counts
-- the saved changes, each one a row of abac_policy_versions.
--
-- abac_policy_versions: append-only snapshots (name, description, condition,
-- status) with who changed it and why. The audit ledger records the same
-- change in the same transaction.
--
-- abac_bindings: the policy that further restricts one catalog item
-- (kind 'catalog_item', target_id the item id): a person must satisfy the
-- listed types and departments and the policy's condition to request it.
-- Birthright rules name their policy inside the rule JSON of
-- business_roles.birthright, so they are versioned with the role.
--
-- Tenant-owned: guard triggers at the end refuse references to another
-- tenant's rows.
CREATE TABLE IF NOT EXISTS abac_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  condition TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS abac_policy_versions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  policy_id TEXT NOT NULL REFERENCES abac_policies (id),
  version INTEGER NOT NULL,
  snapshot TEXT NOT NULL,
  note TEXT,
  changed_by TEXT REFERENCES platform_users (id),
  actor TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  UNIQUE (tenant_id, policy_id, version)
);

CREATE TRIGGER IF NOT EXISTS tg_abac_policy_versions_no_update BEFORE UPDATE ON abac_policy_versions
BEGIN SELECT RAISE(ABORT, 'abac_policy_versions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_abac_policy_versions_no_delete BEFORE DELETE ON abac_policy_versions
BEGIN SELECT RAISE(ABORT, 'abac_policy_versions is append-only'); END;

CREATE TABLE IF NOT EXISTS abac_bindings (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (kind IN ('catalog_item')),
  target_id TEXT NOT NULL,
  policy_id TEXT NOT NULL REFERENCES abac_policies (id),
  bound_by TEXT REFERENCES platform_users (id),
  bound_at TEXT NOT NULL,
  UNIQUE (tenant_id, kind, target_id)
);
CREATE INDEX IF NOT EXISTS ix_abac_bindings_tenant_policy ON abac_bindings (tenant_id, policy_id);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_abac_policies_xtenant_ins BEFORE INSERT ON abac_policies
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: abac_policies'); END;

CREATE TRIGGER IF NOT EXISTS tg_abac_policies_xtenant_upd BEFORE UPDATE OF tenant_id, updated_by ON abac_policies
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: abac_policies'); END;

CREATE TRIGGER IF NOT EXISTS tg_abac_policy_versions_xtenant_ins BEFORE INSERT ON abac_policy_versions
WHEN EXISTS (SELECT 1 FROM abac_policies p WHERE p.id = NEW.policy_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.changed_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.changed_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: abac_policy_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_abac_bindings_xtenant_ins BEFORE INSERT ON abac_bindings
WHEN EXISTS (SELECT 1 FROM abac_policies p WHERE p.id = NEW.policy_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.kind = 'catalog_item' AND EXISTS (SELECT 1 FROM catalog_items p WHERE p.id = NEW.target_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.bound_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.bound_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: abac_bindings'); END;

CREATE TRIGGER IF NOT EXISTS tg_abac_bindings_xtenant_upd BEFORE UPDATE OF tenant_id, policy_id, target_id, bound_by ON abac_bindings
WHEN EXISTS (SELECT 1 FROM abac_policies p WHERE p.id = NEW.policy_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.kind = 'catalog_item' AND EXISTS (SELECT 1 FROM catalog_items p WHERE p.id = NEW.target_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.bound_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.bound_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: abac_bindings'); END;

CREATE TRIGGER IF NOT EXISTS tg_abac_policy_versions_xtenant_upd BEFORE UPDATE OF tenant_id, policy_id, changed_by ON abac_policy_versions
WHEN EXISTS (SELECT 1 FROM abac_policies p WHERE p.id = NEW.policy_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.changed_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.changed_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: abac_policy_versions'); END;
