-- Access request service (issue #164): the requestable catalog, request
-- lines and their history.
--
-- catalog_items describes a requestable group or entitlement: its owner,
-- risk, who may request it (eligible identity types and departments, JSON
-- arrays; empty means anyone) and its durations in hours (NULL default:
-- until removed; NULL max: no limit). An item that is not requestable stays
-- in the table with its metadata.
--
-- access_request_lines are what people asked for: one line per beneficiary
-- and item, grouped by the cart submission (batch_id). Approval and denial
-- are per line. An approved line holds a grant edge (source 'request') from
-- the beneficiary's account to the group, expiring at expires_at (NULL: until
-- removed). Status: pending, approved, denied, cancelled, expired, removed.
--
-- access_request_events is each line's history (submitted, approved,
-- denied, cancelled, expired, removed), append-only; the audit ledger holds
-- the same decisions hash-chained.
--
-- The JIT requests of 0001_tenancy.sql (access_requests) are unchanged.
-- Tenant-owned: guard triggers at the end refuse references to another
-- tenant's rows.
CREATE TABLE IF NOT EXISTS catalog_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id INTEGER NOT NULL REFERENCES groups (id),
  requestable INTEGER NOT NULL DEFAULT 1,
  description TEXT NOT NULL DEFAULT '',
  owner_identity_id INTEGER REFERENCES identities (id),
  risk TEXT NOT NULL DEFAULT 'low' CHECK (risk IN ('low','medium','high')),
  eligible_types TEXT NOT NULL DEFAULT '[]',
  eligible_departments TEXT NOT NULL DEFAULT '[]',
  default_hours REAL CHECK (default_hours IS NULL OR default_hours > 0),
  max_hours REAL CHECK (max_hours IS NULL OR max_hours > 0),
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, group_id)
);

CREATE TABLE IF NOT EXISTS access_request_lines (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  batch_id TEXT NOT NULL,
  catalog_item_id TEXT NOT NULL REFERENCES catalog_items (id),
  group_id INTEGER NOT NULL REFERENCES groups (id),
  beneficiary_id INTEGER NOT NULL REFERENCES identities (id),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  requested_by TEXT NOT NULL REFERENCES platform_users (id),
  justification TEXT NOT NULL,
  duration_hours REAL CHECK (duration_hours IS NULL OR duration_hours > 0),
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','cancelled','expired','removed')),
  requested_at TEXT NOT NULL,
  decided_by TEXT REFERENCES platform_users (id),
  decided_at TEXT,
  decision_reason TEXT,
  edge_id INTEGER REFERENCES grant_edges (id),
  expires_at TEXT,
  closed_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_request_lines_tenant_status ON access_request_lines (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_request_lines_tenant_requester ON access_request_lines (tenant_id, requested_by);
CREATE INDEX IF NOT EXISTS ix_request_lines_tenant_beneficiary ON access_request_lines (tenant_id, beneficiary_id);
CREATE INDEX IF NOT EXISTS ix_request_lines_tenant_batch ON access_request_lines (tenant_id, batch_id);
-- one open line (pending or approved) per beneficiary and group
CREATE UNIQUE INDEX IF NOT EXISTS ux_request_lines_open ON access_request_lines (tenant_id, beneficiary_id, group_id)
  WHERE status IN ('pending','approved');

CREATE TABLE IF NOT EXISTS access_request_events (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  line_id TEXT NOT NULL REFERENCES access_request_lines (id),
  event TEXT NOT NULL CHECK (event IN ('submitted','approved','denied','cancelled','expired','removed')),
  actor_user_id TEXT REFERENCES platform_users (id),
  actor TEXT NOT NULL,
  note TEXT,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_request_events_tenant_line ON access_request_events (tenant_id, line_id);

CREATE TRIGGER IF NOT EXISTS tg_access_request_events_no_update BEFORE UPDATE ON access_request_events
BEGIN SELECT RAISE(ABORT, 'access_request_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_access_request_events_no_delete BEFORE DELETE ON access_request_events
BEGIN SELECT RAISE(ABORT, 'access_request_events is append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_catalog_items_xtenant_ins BEFORE INSERT ON catalog_items
WHEN EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: catalog_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_catalog_items_xtenant_upd BEFORE UPDATE OF tenant_id, group_id, owner_identity_id, updated_by ON catalog_items
WHEN EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.owner_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.owner_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: catalog_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_request_lines_xtenant_ins BEFORE INSERT ON access_request_lines
WHEN EXISTS (SELECT 1 FROM catalog_items p WHERE p.id = NEW.catalog_item_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.beneficiary_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.edge_id IS NOT NULL AND EXISTS (SELECT 1 FROM grant_edges p WHERE p.id = NEW.edge_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_lines'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_request_lines_xtenant_upd BEFORE UPDATE OF tenant_id, catalog_item_id, group_id, beneficiary_id, account_id, requested_by, decided_by, edge_id ON access_request_lines
WHEN EXISTS (SELECT 1 FROM catalog_items p WHERE p.id = NEW.catalog_item_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.beneficiary_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.edge_id IS NOT NULL AND EXISTS (SELECT 1 FROM grant_edges p WHERE p.id = NEW.edge_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_lines'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_request_events_xtenant_ins BEFORE INSERT ON access_request_events
WHEN EXISTS (SELECT 1 FROM access_request_lines p WHERE p.id = NEW.line_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.actor_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.actor_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_events'); END;

CREATE TRIGGER IF NOT EXISTS tg_access_request_events_xtenant_upd BEFORE UPDATE OF tenant_id, line_id, actor_user_id ON access_request_events
WHEN EXISTS (SELECT 1 FROM access_request_lines p WHERE p.id = NEW.line_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.actor_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.actor_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: access_request_events'); END;
