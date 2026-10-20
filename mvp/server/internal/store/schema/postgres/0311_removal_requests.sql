-- Postgres dialect of schema/0311_removal_requests.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE removal_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  beneficiary_id BIGINT NOT NULL,
  account_id BIGINT NOT NULL,
  group_id BIGINT NOT NULL,
  requested_by TEXT NOT NULL,
  justification TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','cancelled')),
  requested_at TEXT NOT NULL,
  decided_by TEXT,
  decided_at TEXT,
  decision_reason TEXT,
  outcome TEXT,
  FOREIGN KEY (tenant_id, beneficiary_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_removal_requests_tenant_status ON removal_requests (tenant_id, status);
CREATE INDEX ix_removal_requests_tenant_beneficiary ON removal_requests (tenant_id, beneficiary_id);
-- one pending removal per person and group
CREATE UNIQUE INDEX ux_removal_requests_pending ON removal_requests (tenant_id, beneficiary_id, group_id)
  WHERE status = 'pending';

CREATE TRIGGER tg_removal_requests_decided_by_xtenant BEFORE INSERT OR UPDATE OF tenant_id, decided_by ON removal_requests
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('platform_users', 'decided_by', 'text');
