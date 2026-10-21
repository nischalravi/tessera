-- Service-account requests (issue #298): a request to create, change or transfer a service
-- account, with mandatory owners (ownership, #167).
--
-- kind: create (a new service identity, and its account in a system), change (purpose,
-- description and backup owner of an existing one) or transfer (a new primary owner, optionally
-- a new backup). status: pending (its workflow's stages are deciding), approved (every stage
-- approved; the change is made and a provisioning operation is in flight, op_id), fulfilled
-- (made, and confirmed or not needing the target), denied, cancelled.
--
-- identity_id is the service account (NULL for create until it is made). primary_owner_id and
-- backup_owner_id are the owners the account has once the request is fulfilled; previous_*
-- are the owners it had when the request was filed (the old owner of a transfer, who must
-- approve). The approval stages are in workflow_stages (request_id; see
-- 0482_workflow_runs.sql).
--
-- Tenant-owned: guard triggers at the end refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS service_account_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  kind TEXT NOT NULL CHECK (kind IN ('create','change','transfer')),
  status TEXT NOT NULL CHECK (status IN ('pending','approved','fulfilled','denied','cancelled')),
  identity_id INTEGER REFERENCES identities (id),
  name TEXT NOT NULL,
  system TEXT NOT NULL DEFAULT '',
  username TEXT NOT NULL DEFAULT '',
  purpose TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  primary_owner_id INTEGER NOT NULL REFERENCES identities (id),
  backup_owner_id INTEGER REFERENCES identities (id),
  previous_primary_id INTEGER REFERENCES identities (id),
  previous_backup_id INTEGER REFERENCES identities (id),
  justification TEXT NOT NULL,
  requested_by TEXT NOT NULL REFERENCES platform_users (id),
  requested_at TEXT NOT NULL,
  decided_by TEXT REFERENCES platform_users (id),
  decided_at TEXT,
  decision_reason TEXT,
  closed_at TEXT,
  fulfilled_at TEXT,
  op_id TEXT
);
CREATE INDEX IF NOT EXISTS ix_sa_requests_tenant_status ON service_account_requests (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_sa_requests_tenant_requester ON service_account_requests (tenant_id, requested_by);
CREATE INDEX IF NOT EXISTS ix_sa_requests_tenant_identity ON service_account_requests (tenant_id, identity_id);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_service_account_requests_xtenant_ins BEFORE INSERT ON service_account_requests
WHEN (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.primary_owner_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.backup_owner_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.backup_owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_primary_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_primary_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_backup_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_backup_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: service_account_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_service_account_requests_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, primary_owner_id, backup_owner_id, previous_primary_id, previous_backup_id, requested_by, decided_by ON service_account_requests
WHEN (NEW.identity_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.primary_owner_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.backup_owner_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.backup_owner_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_primary_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_primary_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.previous_backup_id IS NOT NULL AND EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.previous_backup_id AND p.tenant_id <> NEW.tenant_id))
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: service_account_requests'); END;
