-- Removal requests (My access > Request removal): a person asks for a grant
-- they hold to be removed. The approver is the person's manager, or anyone
-- holding requests.decide; approval removes the grant (through
-- requests.Remove when an approved access request granted it, else as a
-- revoked grant with a tombstone) and denial or cancellation changes nothing.
--
-- account_id and group_id name the grant (account -> group); the edge itself
-- is looked up when the request is decided, so a request survives the edge
-- being rebuilt by a sync. outcome records what approval did (revoked,
-- request_removed or already_removed).
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's identity, account, group or user.
CREATE TABLE IF NOT EXISTS removal_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  beneficiary_id INTEGER NOT NULL REFERENCES identities (id),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  group_id INTEGER NOT NULL REFERENCES groups (id),
  requested_by TEXT NOT NULL REFERENCES platform_users (id),
  justification TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','cancelled')),
  requested_at TEXT NOT NULL,
  decided_by TEXT REFERENCES platform_users (id),
  decided_at TEXT,
  decision_reason TEXT,
  outcome TEXT
);
CREATE INDEX IF NOT EXISTS ix_removal_requests_tenant_status ON removal_requests (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_removal_requests_tenant_beneficiary ON removal_requests (tenant_id, beneficiary_id);
-- one pending removal per person and group
CREATE UNIQUE INDEX IF NOT EXISTS ux_removal_requests_pending ON removal_requests (tenant_id, beneficiary_id, group_id)
  WHERE status = 'pending';

CREATE TRIGGER IF NOT EXISTS tg_removal_requests_xtenant_ins BEFORE INSERT ON removal_requests
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.beneficiary_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: removal_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_removal_requests_xtenant_upd BEFORE UPDATE OF tenant_id, beneficiary_id, account_id, group_id, requested_by, decided_by ON removal_requests
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.beneficiary_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.requested_by AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.decided_by IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.decided_by AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: removal_requests'); END;
