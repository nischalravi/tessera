-- Identity lifecycle (issue #159): worker type, sponsor and dates.
--
-- identity_lifecycle holds one row per identity that has lifecycle data; an
-- identity without a row is an employee with no end date. worker_type is
-- employee, contractor, intern, partner, vendor or guest. Every type but
-- employee has an end date and a sponsor (the person accountable for them).
-- starts_at in the future means the identity has not started yet. On
-- ends_at the expiry sweep runs the leaver plan (disable accounts, remove
-- grants, cancel JIT, reassign ownership) and sets ended_at. warned_days is
-- the smallest warning threshold already sent (14, 7, 1), so each warning
-- goes out once; an extension resets it.
--
-- identity_lifecycle_events is the history (set, extended, converted,
-- warned, ended), append-only; the audit ledger holds the same changes
-- hash-chained.
--
-- source 'sponsorship' marks a row written from the person's sponsorships (issue #65):
-- while one is live the sponsorships own the row and the API refuses to edit it.
--
-- Tenant-owned: guard triggers refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS identity_lifecycle (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  worker_type TEXT NOT NULL CHECK (worker_type IN ('employee','contractor','intern','partner','vendor','guest')),
  sponsor_identity_id INTEGER REFERENCES identities (id),
  organization TEXT,
  starts_at TEXT,
  ends_at TEXT,
  warned_days INTEGER,
  ended_at TEXT,
  source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','hris','sponsorship')),
  updated_by TEXT REFERENCES platform_users (id),
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, identity_id),
  CHECK (worker_type = 'employee' OR ends_at IS NOT NULL),
  CHECK (starts_at IS NULL OR ends_at IS NULL OR ends_at > starts_at)
);
CREATE INDEX IF NOT EXISTS ix_identity_lifecycle_tenant_ends ON identity_lifecycle (tenant_id, ends_at);
CREATE INDEX IF NOT EXISTS ix_identity_lifecycle_tenant_sponsor ON identity_lifecycle (tenant_id, sponsor_identity_id);

CREATE TABLE IF NOT EXISTS identity_lifecycle_events (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  event TEXT NOT NULL CHECK (event IN ('set','extended','converted','warned','ended')),
  worker_type TEXT,
  ends_at TEXT,
  note TEXT,
  actor_user_id TEXT REFERENCES platform_users (id),
  actor TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_lifecycle_events_tenant_identity ON identity_lifecycle_events (tenant_id, identity_id);

CREATE TRIGGER IF NOT EXISTS tg_identity_lifecycle_events_no_update BEFORE UPDATE ON identity_lifecycle_events
BEGIN SELECT RAISE(ABORT, 'identity_lifecycle_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_identity_lifecycle_events_no_delete BEFORE DELETE ON identity_lifecycle_events
BEGIN SELECT RAISE(ABORT, 'identity_lifecycle_events is append-only'); END;

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_identity_lifecycle_xtenant_ins BEFORE INSERT ON identity_lifecycle
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.sponsor_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_lifecycle'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_lifecycle_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, sponsor_identity_id, updated_by ON identity_lifecycle
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.sponsor_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.sponsor_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.updated_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.updated_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_lifecycle'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_lifecycle_events_xtenant_ins BEFORE INSERT ON identity_lifecycle_events
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.actor_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.actor_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_lifecycle_events'); END;

CREATE TRIGGER IF NOT EXISTS tg_identity_lifecycle_events_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, actor_user_id ON identity_lifecycle_events
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.actor_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.actor_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: identity_lifecycle_events'); END;
