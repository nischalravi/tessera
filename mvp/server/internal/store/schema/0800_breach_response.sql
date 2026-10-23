-- Vendor breach response (issue #475). A vendor was breached (Railway,
-- GhostAction): every credential tied to it must be rotated or revoked, and
-- shown to be. A breach plan is the tracked record of that work: one row per
-- plan, one item per credential (a secret, an OAuth grant, a GitHub token, a
-- service account). The work itself is done by the existing machinery, the
-- rotation bulk run (0225_rotation.sql) for secrets and the OAuth revoke
-- (0361_oauth_apps.sql) for grants; the plan links to them and re-reads their
-- state to verify. No secret material is stored: labels and references only.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's row.

CREATE TABLE IF NOT EXISTS breach_plans (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  vendor TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) >= 10),
  status TEXT NOT NULL CHECK (status IN ('planned','running','completed')),
  bulk_id TEXT REFERENCES rotation_bulks (id),
  created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  started_by TEXT, started_at TEXT,
  completed_at TEXT,
  report TEXT
);
CREATE INDEX IF NOT EXISTS breach_plans_tenant ON breach_plans(tenant_id, created_at);

-- One credential of the plan. action is what the plan does with it: rotate
-- (a rotation job), revoke (an OAuth revoke) or manual (a person does it and
-- attests, unless a re-read already shows it gone). state: pending,
-- in_progress (queued or revoked, not yet re-read), verified (a re-read shows
-- it rotated or gone), attested (a person confirmed a manual item) or failed.
CREATE TABLE IF NOT EXISTS breach_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  plan_id TEXT NOT NULL REFERENCES breach_plans (id),
  kind TEXT NOT NULL CHECK (kind IN ('secret','oauth_grant','github_token','service_account')),
  ref TEXT NOT NULL,
  label TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('rotate','revoke','manual')),
  state TEXT NOT NULL CHECK (state IN ('pending','in_progress','verified','attested','failed')),
  detail TEXT NOT NULL DEFAULT '',
  verification TEXT,
  verified_at TEXT,
  attested_by TEXT, attested_note TEXT,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, plan_id, kind, ref)
);
CREATE INDEX IF NOT EXISTS breach_items_plan ON breach_items(tenant_id, plan_id);

CREATE TRIGGER IF NOT EXISTS tg_breach_plans_xtenant_ins BEFORE INSERT ON breach_plans
WHEN NEW.bulk_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_bulks p WHERE p.id = NEW.bulk_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: breach_plans'); END;

CREATE TRIGGER IF NOT EXISTS tg_breach_plans_xtenant_upd BEFORE UPDATE OF tenant_id, bulk_id ON breach_plans
WHEN NEW.bulk_id IS NOT NULL AND EXISTS (SELECT 1 FROM rotation_bulks p WHERE p.id = NEW.bulk_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: breach_plans'); END;

CREATE TRIGGER IF NOT EXISTS tg_breach_items_xtenant_ins BEFORE INSERT ON breach_items
WHEN EXISTS (SELECT 1 FROM breach_plans p WHERE p.id = NEW.plan_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: breach_items'); END;

CREATE TRIGGER IF NOT EXISTS tg_breach_items_xtenant_upd BEFORE UPDATE OF tenant_id, plan_id ON breach_items
WHEN EXISTS (SELECT 1 FROM breach_plans p WHERE p.id = NEW.plan_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: breach_items'); END;
