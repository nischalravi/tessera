-- Workflow runs (issue #298): what a workflow definition resolved to for one request.
--
-- workflow_runs is one row per routed subject: an access request line (subject_kind
-- access_line, subject_id the line id; its approval stages stay in access_request_stages,
-- #165) or a service-account request (service_account_request; stages in workflow_stages
-- below). plan is the resolved path as JSON (see internal/workflow.Plan): the steps taken after
-- the definition's conditions were evaluated against the request's attributes, with the
-- approver group, hold time and label of each approval stage and the notify, questionnaire and
-- provisioning actions anchored to a stage. The run keeps the workflow version it started
-- with, so a later edit does not reroute it. status: running, completed (every stage
-- approved), denied, cancelled.
--
-- workflow_stages are the approval stages of a service-account request (0481), the same shape as
-- access_request_stages (request_id is the request): kind manager, owner or decider; the assignee is the identity resolved
-- when the request was filed (NULL for decider, or when there is none, which escalates at
-- once); status queued, waiting, approved, denied, closed.
--
-- Tenant-owned: guard triggers at the end refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS workflow_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  workflow_id TEXT NOT NULL REFERENCES workflows (id),
  version INTEGER NOT NULL,
  subject_kind TEXT NOT NULL CHECK (subject_kind IN ('access_line','service_account_request')),
  subject_id TEXT NOT NULL,
  plan TEXT NOT NULL CHECK (json_valid(plan)),
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','denied','cancelled')),
  started_at TEXT NOT NULL,
  finished_at TEXT,
  UNIQUE (tenant_id, subject_kind, subject_id),
  FOREIGN KEY (tenant_id, workflow_id, version) REFERENCES workflow_versions (tenant_id, workflow_id, version)
);
CREATE INDEX IF NOT EXISTS ix_workflow_runs_tenant_workflow ON workflow_runs (tenant_id, workflow_id);

CREATE TABLE IF NOT EXISTS workflow_stages (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  request_id TEXT NOT NULL REFERENCES service_account_requests (id),
  idx INTEGER NOT NULL CHECK (idx >= 0),
  kind TEXT NOT NULL CHECK (kind IN ('manager','owner','decider')),
  assignee_identity_id INTEGER REFERENCES identities (id),
  status TEXT NOT NULL CHECK (status IN ('queued','waiting','approved','denied','closed')),
  started_at TEXT,
  due_at TEXT,
  decided_by TEXT REFERENCES platform_users (id),
  on_behalf_of TEXT REFERENCES platform_users (id),
  decided_at TEXT,
  reason TEXT,
  PRIMARY KEY (tenant_id, request_id, idx)
);
CREATE INDEX IF NOT EXISTS ix_workflow_stages_tenant_status ON workflow_stages (tenant_id, status);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_workflow_runs_xtenant_ins BEFORE INSERT ON workflow_runs
WHEN EXISTS (SELECT 1 FROM workflows p WHERE p.id = NEW.workflow_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM workflow_versions p WHERE p.workflow_id = NEW.workflow_id AND p.version = NEW.version AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: workflow_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_workflow_runs_xtenant_upd BEFORE UPDATE OF tenant_id, workflow_id, version ON workflow_runs
WHEN EXISTS (SELECT 1 FROM workflows p WHERE p.id = NEW.workflow_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM workflow_versions p WHERE p.workflow_id = NEW.workflow_id AND p.version = NEW.version AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: workflow_runs'); END;

CREATE TRIGGER IF NOT EXISTS tg_workflow_stages_xtenant_ins BEFORE INSERT ON workflow_stages
WHEN EXISTS (SELECT 1 FROM service_account_requests p WHERE p.id = NEW.request_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.assignee_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.assignee_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.on_behalf_of IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.on_behalf_of AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: workflow_stages'); END;

CREATE TRIGGER IF NOT EXISTS tg_workflow_stages_xtenant_upd BEFORE UPDATE OF tenant_id, request_id, assignee_identity_id, decided_by, on_behalf_of ON workflow_stages
WHEN EXISTS (SELECT 1 FROM service_account_requests p WHERE p.id = NEW.request_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.assignee_identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.assignee_identity_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.on_behalf_of IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.on_behalf_of AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: workflow_stages'); END;
