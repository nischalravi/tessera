-- Workflow designer (issue #298): configurable, versioned workflow definitions that route
-- approvals.
--
-- workflows is a definition's identity and its current version. scope says what it routes:
-- 'access' (access request lines) or 'service_account' (service-account requests).
-- workflow_versions holds every version's steps (a JSON document; see internal/workflow),
-- append-only: editing inserts the next version, so a run always points at the exact
-- definition it ran. status 'retired' stops new use (its assignments are removed); runs in
-- flight finish on the version they started with.
--
-- workflow_assignments say what a workflow routes. target_kind is catalog_item (target_id is
-- the item's id; scope access) or request_type (target_id is access, service_account_create,
-- service_account_change or service_account_transfer). One workflow per target; a catalog
-- item's own assignment wins over the access request type's. A target with no assignment keeps
-- today's routing (the item's approval policy, #165).
--
-- Tenant-owned: guard triggers at the end refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS workflows (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('access','service_account')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS workflow_versions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  workflow_id TEXT NOT NULL REFERENCES workflows (id),
  version INTEGER NOT NULL CHECK (version >= 1),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  definition TEXT NOT NULL CHECK (json_valid(definition)),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, workflow_id, version)
);

CREATE TRIGGER IF NOT EXISTS tg_workflow_versions_no_update BEFORE UPDATE ON workflow_versions
BEGIN SELECT RAISE(ABORT, 'workflow_versions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_workflow_versions_no_delete BEFORE DELETE ON workflow_versions
BEGIN SELECT RAISE(ABORT, 'workflow_versions is append-only'); END;

CREATE TABLE IF NOT EXISTS workflow_assignments (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  workflow_id TEXT NOT NULL REFERENCES workflows (id),
  target_kind TEXT NOT NULL CHECK (target_kind IN ('catalog_item','request_type')),
  target_id TEXT NOT NULL,
  UNIQUE (tenant_id, target_kind, target_id)
);
CREATE INDEX IF NOT EXISTS ix_workflow_assignments_tenant_w ON workflow_assignments (tenant_id, workflow_id);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_workflow_versions_xtenant_ins BEFORE INSERT ON workflow_versions
WHEN EXISTS (SELECT 1 FROM workflows p WHERE p.id = NEW.workflow_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: workflow_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_workflow_versions_xtenant_upd BEFORE UPDATE OF tenant_id, workflow_id ON workflow_versions
WHEN EXISTS (SELECT 1 FROM workflows p WHERE p.id = NEW.workflow_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: workflow_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_workflow_assignments_xtenant_ins BEFORE INSERT ON workflow_assignments
WHEN EXISTS (SELECT 1 FROM workflows p WHERE p.id = NEW.workflow_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: workflow_assignments'); END;

CREATE TRIGGER IF NOT EXISTS tg_workflow_assignments_xtenant_upd BEFORE UPDATE OF tenant_id, workflow_id ON workflow_assignments
WHEN EXISTS (SELECT 1 FROM workflows p WHERE p.id = NEW.workflow_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: workflow_assignments'); END;
