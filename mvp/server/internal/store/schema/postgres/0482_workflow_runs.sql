-- Postgres dialect of schema/0481_workflow_runs.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); json_valid is IS JSON.

-- +goose Up

CREATE TABLE workflow_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  workflow_id TEXT NOT NULL,
  version BIGINT NOT NULL,
  subject_kind TEXT NOT NULL CHECK (subject_kind IN ('access_line','service_account_request')),
  subject_id TEXT NOT NULL,
  plan TEXT NOT NULL CHECK (plan IS JSON),
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','denied','cancelled')),
  started_at TEXT NOT NULL,
  finished_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, subject_kind, subject_id),
  FOREIGN KEY (tenant_id, workflow_id) REFERENCES workflows (tenant_id, id),
  FOREIGN KEY (tenant_id, workflow_id, version) REFERENCES workflow_versions (tenant_id, workflow_id, version)
);

CREATE INDEX ix_workflow_runs_tenant_workflow ON workflow_runs (tenant_id, workflow_id);

CREATE TABLE workflow_stages (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  request_id TEXT NOT NULL,
  idx BIGINT NOT NULL CHECK (idx >= 0),
  kind TEXT NOT NULL CHECK (kind IN ('manager','owner','decider')),
  assignee_identity_id BIGINT,
  status TEXT NOT NULL CHECK (status IN ('queued','waiting','approved','denied','closed')),
  started_at TEXT,
  due_at TEXT,
  decided_by TEXT,
  on_behalf_of TEXT,
  decided_at TEXT,
  reason TEXT,
  PRIMARY KEY (tenant_id, request_id, idx),
  FOREIGN KEY (tenant_id, request_id) REFERENCES service_account_requests (tenant_id, id),
  FOREIGN KEY (tenant_id, assignee_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, on_behalf_of) REFERENCES platform_users (tenant_id, id)
);

CREATE INDEX ix_workflow_stages_tenant_status ON workflow_stages (tenant_id, status);
