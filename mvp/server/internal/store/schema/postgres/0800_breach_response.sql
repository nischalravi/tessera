-- Postgres dialect of schema/0800_breach_response.sql (issue #475). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE breach_plans (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  vendor TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) >= 10),
  status TEXT NOT NULL CHECK (status IN ('planned','running','completed')),
  bulk_id TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  started_by TEXT, started_at TEXT,
  completed_at TEXT,
  report TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, bulk_id) REFERENCES rotation_bulks (tenant_id, id)
);
CREATE INDEX breach_plans_tenant ON breach_plans(tenant_id, created_at);

CREATE TABLE breach_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  plan_id TEXT NOT NULL,
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
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, plan_id, kind, ref),
  FOREIGN KEY (tenant_id, plan_id) REFERENCES breach_plans (tenant_id, id)
);
CREATE INDEX breach_items_plan ON breach_items(tenant_id, plan_id);
