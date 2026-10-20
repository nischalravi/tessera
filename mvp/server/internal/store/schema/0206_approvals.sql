-- Approval routing (issue #165): who approves a request line, in which
-- order, and who may act for whom.
--
-- approval_policies names a catalog item's stages, in order (JSON array of
-- 'manager' | 'owner' | 'decider'), and how many hours a stage waits before
-- it escalates to every holder of requests.decide. An item without a policy
-- has one 'decider' stage.
--
-- access_request_stages are a line's stages, copied from the policy when the
-- line is filed (a later policy change does not reroute it). The assignee is
-- the identity resolved then (the beneficiary's manager, the item's owner;
-- NULL for 'decider' or when there is none, which escalates at once).
-- Status: queued (a later stage), waiting (the current one), approved,
-- denied, closed (the line ended another way).
--
-- approval_delegations hand one user's approvals to another for a time
-- window. They never let anyone approve their own request or access.
CREATE TABLE IF NOT EXISTS approval_policies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  catalog_item_id TEXT NOT NULL REFERENCES catalog_items (id),
  stages TEXT NOT NULL,
  escalate_after_hours REAL NOT NULL DEFAULT 48 CHECK (escalate_after_hours > 0),
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, catalog_item_id)
);

CREATE TABLE IF NOT EXISTS access_request_stages (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  line_id TEXT NOT NULL REFERENCES access_request_lines (id),
  idx INTEGER NOT NULL CHECK (idx >= 0),
  kind TEXT NOT NULL CHECK (kind IN ('manager','owner','decider','sponsor')),
  assignee_identity_id INTEGER REFERENCES identities (id),
  status TEXT NOT NULL CHECK (status IN ('queued','waiting','approved','denied','closed')),
  started_at TEXT,
  due_at TEXT,
  decided_by TEXT REFERENCES platform_users (id),
  on_behalf_of TEXT REFERENCES platform_users (id),
  decided_at TEXT,
  reason TEXT,
  PRIMARY KEY (tenant_id, line_id, idx)
);
CREATE INDEX IF NOT EXISTS ix_request_stages_tenant_status ON access_request_stages (tenant_id, status);

CREATE TABLE IF NOT EXISTS approval_delegations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  from_user TEXT NOT NULL REFERENCES platform_users (id),
  to_user TEXT NOT NULL REFERENCES platform_users (id),
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_by TEXT REFERENCES platform_users (id),
  CHECK (from_user <> to_user),
  CHECK (ends_at > starts_at)
);
CREATE INDEX IF NOT EXISTS ix_approval_delegations_tenant_to ON approval_delegations (tenant_id, to_user);
CREATE INDEX IF NOT EXISTS ix_approval_delegations_tenant_from ON approval_delegations (tenant_id, from_user);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_approval_policies_xtenant_ins BEFORE INSERT ON approval_policies
WHEN EXISTS (SELECT 1 FROM catalog_items p WHERE p.id = NEW.catalog_item_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: approval_policies'); END;

CREATE TRIGGER IF NOT EXISTS tg_approval_policies_xtenant_upd BEFORE UPDATE OF tenant_id, catalog_item_id, updated_by ON approval_policies
WHEN EXISTS (SELECT 1 FROM catalog_items p WHERE p.id = NEW.catalog_item_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: approval_policies'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_request_stages_xtenant_ins BEFORE INSERT ON access_request_stages
WHEN EXISTS (SELECT 1 FROM access_request_lines p WHERE p.id = NEW.line_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.assignee_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.assignee_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.on_behalf_of IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.on_behalf_of AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_stages'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_request_stages_xtenant_upd BEFORE UPDATE OF tenant_id, line_id, assignee_identity_id, decided_by, on_behalf_of ON access_request_stages
WHEN EXISTS (SELECT 1 FROM access_request_lines p WHERE p.id = NEW.line_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.assignee_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.assignee_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.on_behalf_of IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.on_behalf_of AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_stages'); END;

CREATE TRIGGER IF NOT EXISTS tg_approval_delegations_xtenant_ins BEFORE INSERT ON approval_delegations
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.from_user AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.to_user AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.revoked_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.revoked_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: approval_delegations'); END;

CREATE TRIGGER IF NOT EXISTS tg_approval_delegations_xtenant_upd BEFORE UPDATE OF tenant_id, from_user, to_user, revoked_by ON approval_delegations
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.from_user AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.to_user AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.revoked_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.revoked_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: approval_delegations'); END;
