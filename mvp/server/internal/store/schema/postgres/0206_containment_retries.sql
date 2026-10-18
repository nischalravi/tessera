-- Postgres dialect of schema/0206_containment_retries.sql (Phase 0 PR14). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE containment_retries (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id BIGINT NOT NULL,
  account_id BIGINT NOT NULL,
  connection_id TEXT,
  system TEXT NOT NULL,
  account_label TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('revoke_sessions','revoke_grants')),
  trigger TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','succeeded','gave_up')),
  attempts BIGINT NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections (tenant_id, id)
);
CREATE INDEX ix_containment_retries_due ON containment_retries (tenant_id, status, next_attempt_at);
CREATE INDEX ix_containment_retries_identity ON containment_retries (tenant_id, identity_id);
-- one open retry per account and step
CREATE UNIQUE INDEX ux_containment_retries_open ON containment_retries (tenant_id, account_id, action) WHERE status = 'pending';
