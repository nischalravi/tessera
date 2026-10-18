-- Postgres dialect of schema/0006_admin.sql (Phase 0 PR14). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE bootstrap_invitations (
  rowid BIGINT GENERATED ALWAYS AS IDENTITY,
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
  idp_connection_id TEXT NOT NULL,
  email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
  role TEXT NOT NULL DEFAULT 'tenant_admin' CHECK (role = 'tenant_admin'),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  consumed_at TEXT, consumed_by_user_id TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, code_hash),
  CHECK (created_at < expires_at),
  CHECK ((consumed_at IS NULL) = (consumed_by_user_id IS NULL)),
  FOREIGN KEY (tenant_id, idp_connection_id) REFERENCES idp_connections (tenant_id, id),
  FOREIGN KEY (tenant_id, consumed_by_user_id) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX bootstrap_invitations_tenant ON bootstrap_invitations(tenant_id);

-- login_transactions.bootstrap_invitation_id (0005) names an invitation of the
-- same tenant.
ALTER TABLE login_transactions ADD FOREIGN KEY (tenant_id, bootstrap_invitation_id) REFERENCES bootstrap_invitations (tenant_id, id);
