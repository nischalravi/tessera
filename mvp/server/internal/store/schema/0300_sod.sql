-- Separation of duties as functions, risks and rulesets (issue #298).
--
-- sod_functions: a named, reusable set of entitlements. `selectors` is JSON, a
-- list of {system, entitlement_id | name_pattern, attribute, value}: a system
-- plus a permission id or an action name pattern, optionally narrowed by a
-- resource attribute (the fine-grained "auth object / field / value" case).
--
-- sod_rulesets: a named group of risks, enabled or disabled for the tenant.
--
-- sod_risks: a named, prioritised conflict between two or more functions
-- (sod_risk_functions). An identity violates a risk when it effectively holds
-- an entitlement of each of two of the risk's functions, by any path in the
-- graph. `subjects` is JSON ({identity_types, statuses, condition}) and limits
-- who the risk is checked for; '{}' means active identities of every type.
-- Every risk belongs to one ruleset.
--
-- sod_versions: append-only snapshots of every saved change to a function, a
-- risk or a ruleset (kind), with who changed it and why. The audit ledger
-- records the same change in the same transaction.
--
-- Tenant-owned: guard triggers at the end refuse references to another
-- tenant's rows.
CREATE TABLE IF NOT EXISTS sod_functions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  owner_identity_id INTEGER REFERENCES identities (id),
  selectors TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, key),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS sod_rulesets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, key),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS sod_risks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  priority TEXT NOT NULL CHECK (priority IN ('critical','high','medium','low')),
  business_process TEXT NOT NULL DEFAULT '',
  owner_identity_id INTEGER REFERENCES identities (id),
  ruleset_id TEXT NOT NULL REFERENCES sod_rulesets (id),
  subjects TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, key),
  UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS ix_sod_risks_tenant_ruleset ON sod_risks (tenant_id, ruleset_id);

CREATE TABLE IF NOT EXISTS sod_risk_functions (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  risk_id TEXT NOT NULL REFERENCES sod_risks (id),
  function_id TEXT NOT NULL REFERENCES sod_functions (id),
  ord INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, risk_id, function_id)
);
CREATE INDEX IF NOT EXISTS ix_sod_risk_functions_tenant_function ON sod_risk_functions (tenant_id, function_id);

CREATE TABLE IF NOT EXISTS sod_versions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (kind IN ('function','risk','ruleset')),
  object_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  snapshot TEXT NOT NULL,
  note TEXT,
  changed_by TEXT REFERENCES platform_users (id),
  actor TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  UNIQUE (tenant_id, kind, object_id, version)
);

CREATE TRIGGER IF NOT EXISTS tg_sod_versions_no_update BEFORE UPDATE ON sod_versions
BEGIN SELECT RAISE(ABORT, 'sod_versions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_sod_versions_no_delete BEFORE DELETE ON sod_versions
BEGIN SELECT RAISE(ABORT, 'sod_versions is append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_sod_functions_xtenant_ins BEFORE INSERT ON sod_functions
WHEN (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.owner_identity_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_functions'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_functions_xtenant_upd BEFORE UPDATE OF tenant_id, updated_by, owner_identity_id ON sod_functions
WHEN (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.owner_identity_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_functions'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_rulesets_xtenant_ins BEFORE INSERT ON sod_rulesets
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_rulesets'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_rulesets_xtenant_upd BEFORE UPDATE OF tenant_id, updated_by ON sod_rulesets
WHEN NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_rulesets'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_risks_xtenant_ins BEFORE INSERT ON sod_risks
WHEN EXISTS (SELECT 1 FROM sod_rulesets r WHERE r.id = NEW.ruleset_id AND r.tenant_id <> NEW.tenant_id)
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.owner_identity_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_risks'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_risks_xtenant_upd BEFORE UPDATE OF tenant_id, ruleset_id, updated_by, owner_identity_id ON sod_risks
WHEN EXISTS (SELECT 1 FROM sod_rulesets r WHERE r.id = NEW.ruleset_id AND r.tenant_id <> NEW.tenant_id)
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities i WHERE i.id = NEW.owner_identity_id AND i.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_risks'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_risk_functions_xtenant_ins BEFORE INSERT ON sod_risk_functions
WHEN EXISTS (SELECT 1 FROM sod_risks r WHERE r.id = NEW.risk_id AND r.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM sod_functions f WHERE f.id = NEW.function_id AND f.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_risk_functions'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_risk_functions_xtenant_upd BEFORE UPDATE OF tenant_id, risk_id, function_id ON sod_risk_functions
WHEN EXISTS (SELECT 1 FROM sod_risks r WHERE r.id = NEW.risk_id AND r.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM sod_functions f WHERE f.id = NEW.function_id AND f.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_risk_functions'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_versions_xtenant_ins BEFORE INSERT ON sod_versions
WHEN (NEW.kind = 'function' AND EXISTS (SELECT 1 FROM sod_functions o WHERE o.id = NEW.object_id AND o.tenant_id <> NEW.tenant_id))
	OR (NEW.kind = 'risk' AND EXISTS (SELECT 1 FROM sod_risks o WHERE o.id = NEW.object_id AND o.tenant_id <> NEW.tenant_id))
	OR (NEW.kind = 'ruleset' AND EXISTS (SELECT 1 FROM sod_rulesets o WHERE o.id = NEW.object_id AND o.tenant_id <> NEW.tenant_id))
	OR (NEW.changed_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.changed_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_sod_versions_xtenant_upd BEFORE UPDATE OF tenant_id, object_id, changed_by ON sod_versions
WHEN (NEW.kind = 'function' AND EXISTS (SELECT 1 FROM sod_functions o WHERE o.id = NEW.object_id AND o.tenant_id <> NEW.tenant_id))
	OR (NEW.kind = 'risk' AND EXISTS (SELECT 1 FROM sod_risks o WHERE o.id = NEW.object_id AND o.tenant_id <> NEW.tenant_id))
	OR (NEW.kind = 'ruleset' AND EXISTS (SELECT 1 FROM sod_rulesets o WHERE o.id = NEW.object_id AND o.tenant_id <> NEW.tenant_id))
	OR (NEW.changed_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.changed_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: sod_versions'); END;
