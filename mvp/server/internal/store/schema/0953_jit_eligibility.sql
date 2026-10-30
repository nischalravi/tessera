-- JIT eligibility as code (issue #651, AC-5; design docs/design/access-as-code-repo.md sections 3.3 and 5): who may
-- ask for which group, for how long, who approves it and whether the approval needs step-up.
--
-- jit_settings: one row per tenant once eligibility has been applied. enabled = 0 (or no row): groups.requestable
-- decides what may be requested, as before. enabled = 1: deny by default; a request must match an active
-- jit_eligibility row (jit.CreateRequest, jit.Approve).
--
-- jit_eligibility: one rule per key (jit/<key>.yaml in the policy repository); status active or retired (a retired
-- rule is kept, never deleted); max_hours is 1 to 72 (jit.MaxHours); min_approvals is 0 or 1 in v1; version counts
-- the changes, each one a row of jit_eligibility_versions.
--
-- jit_eligibility_groups: the groups a rule names, by role: principal (membership lets a person ask),
-- entitlement (what may be asked for) and approver (membership lets a person approve; none: any jit.decide holder).
--
-- jit_eligibility_versions: append-only snapshots of each change with the policy_ref {commit, path, bundle_sha256}
-- of the repository change that made it.
--
-- Tenant-owned: tenant_id on every row, every unique index starts with it, guard triggers at the end refuse
-- references to another tenant's rows.
CREATE TABLE IF NOT EXISTS jit_settings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id)
);

CREATE TABLE IF NOT EXISTS jit_eligibility (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  max_hours INTEGER NOT NULL CHECK (max_hours BETWEEN 1 AND 72),
  min_approvals INTEGER NOT NULL DEFAULT 0 CHECK (min_approvals BETWEEN 0 AND 1),
  step_up INTEGER NOT NULL DEFAULT 0 CHECK (step_up IN (0, 1)),
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, key)
);

CREATE TABLE IF NOT EXISTS jit_eligibility_groups (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  eligibility_id TEXT NOT NULL REFERENCES jit_eligibility (id),
  role TEXT NOT NULL CHECK (role IN ('principal','entitlement','approver')),
  group_id INTEGER NOT NULL REFERENCES groups (id),
  UNIQUE (tenant_id, eligibility_id, role, group_id)
);
CREATE INDEX IF NOT EXISTS ix_jit_eligibility_groups_tenant_group ON jit_eligibility_groups (tenant_id, group_id);

CREATE TABLE IF NOT EXISTS jit_eligibility_versions (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  eligibility_id TEXT NOT NULL REFERENCES jit_eligibility (id),
  version INTEGER NOT NULL,
  snapshot TEXT NOT NULL,
  actor TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  policy_ref TEXT,
  UNIQUE (tenant_id, eligibility_id, version)
);

CREATE TRIGGER IF NOT EXISTS tg_jit_eligibility_versions_no_update BEFORE UPDATE ON jit_eligibility_versions
BEGIN SELECT RAISE(ABORT, 'jit_eligibility_versions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_jit_eligibility_versions_no_delete BEFORE DELETE ON jit_eligibility_versions
BEGIN SELECT RAISE(ABORT, 'jit_eligibility_versions is append-only'); END;

-- Cross-tenant reference guards (same pattern as 0206_business_roles.sql).

CREATE TRIGGER IF NOT EXISTS tg_jit_eligibility_groups_xtenant_ins BEFORE INSERT ON jit_eligibility_groups
WHEN EXISTS (SELECT 1 FROM jit_eligibility p WHERE p.id = NEW.eligibility_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: jit_eligibility_groups'); END;

CREATE TRIGGER IF NOT EXISTS tg_jit_eligibility_groups_xtenant_upd BEFORE UPDATE OF tenant_id, eligibility_id, group_id ON jit_eligibility_groups
WHEN EXISTS (SELECT 1 FROM jit_eligibility p WHERE p.id = NEW.eligibility_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: jit_eligibility_groups'); END;

CREATE TRIGGER IF NOT EXISTS tg_jit_eligibility_versions_xtenant_ins BEFORE INSERT ON jit_eligibility_versions
WHEN EXISTS (SELECT 1 FROM jit_eligibility p WHERE p.id = NEW.eligibility_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: jit_eligibility_versions'); END;

CREATE TRIGGER IF NOT EXISTS tg_jit_eligibility_versions_xtenant_upd BEFORE UPDATE OF tenant_id, eligibility_id ON jit_eligibility_versions
WHEN EXISTS (SELECT 1 FROM jit_eligibility p WHERE p.id = NEW.eligibility_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: jit_eligibility_versions'); END;
