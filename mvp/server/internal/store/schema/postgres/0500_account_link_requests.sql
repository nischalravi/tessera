-- Postgres dialect of schema/0500_account_link_requests.sql (issue #376). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE account_link_requests (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  account_id BIGINT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('link','release')),
  identity_id BIGINT,
  previous_identity_id BIGINT,
  reason TEXT NOT NULL,
  requested_by_user_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  CHECK ((action = 'link') = (identity_id IS NOT NULL)),
  PRIMARY KEY (tenant_id, account_id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, previous_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by_user_id) REFERENCES platform_users (tenant_id, id)
);
