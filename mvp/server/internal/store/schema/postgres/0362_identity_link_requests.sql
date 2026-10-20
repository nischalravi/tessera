-- Postgres dialect of schema/0362_identity_link_requests.sql (issue #357). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE identity_link_requests (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT NOT NULL,
  identity_id BIGINT,
  previous_identity_id BIGINT,
  requested_by_user_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, previous_identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by_user_id) REFERENCES platform_users (tenant_id, id)
);
