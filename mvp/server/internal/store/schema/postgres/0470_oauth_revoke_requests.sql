-- Postgres dialect of schema/0470_oauth_revoke_requests.sql (issue #107). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE oauth_revoke_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  scope TEXT NOT NULL CHECK (scope IN ('app','vendor')),
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  apps INTEGER NOT NULL DEFAULT 0,
  grants INTEGER NOT NULL DEFAULT 0,
  requested_by_user_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','executed','expired')),
  decided_by_user_id TEXT,
  decided_by TEXT,
  decided_at TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by_user_id) REFERENCES platform_users (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by_user_id) REFERENCES platform_users (tenant_id, id)
);
CREATE INDEX ix_oauth_revoke_requests_target ON oauth_revoke_requests (tenant_id, scope, target, status);
