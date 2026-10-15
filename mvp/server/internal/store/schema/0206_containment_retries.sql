-- Containment retry tasks (issue #106): a containment step (revoke_sessions or
-- revoke_grants) that failed while a leaver went ahead, or that failed in a
-- manual contain, is retried by a background sweeper with backoff until it
-- succeeds (re-read verified) or is given up on after about 24 hours.
-- A gave_up row stays listed as the manual task: someone must revoke by hand.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's identity, account or connection.
CREATE TABLE IF NOT EXISTS containment_retries (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  connection_id TEXT REFERENCES connections (id),
  system TEXT NOT NULL,
  account_label TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('revoke_sessions','revoke_grants')),
  trigger TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','succeeded','gave_up')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_containment_retries_due ON containment_retries (tenant_id, status, next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_containment_retries_identity ON containment_retries (tenant_id, identity_id);
-- one open retry per account and step
CREATE UNIQUE INDEX IF NOT EXISTS ux_containment_retries_open ON containment_retries (tenant_id, account_id, action) WHERE status = 'pending';

CREATE TRIGGER IF NOT EXISTS tg_containment_retries_xtenant_ins BEFORE INSERT ON containment_retries
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: containment_retries'); END;

CREATE TRIGGER IF NOT EXISTS tg_containment_retries_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id, account_id, connection_id ON containment_retries
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM accounts p WHERE p.id = NEW.account_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: containment_retries'); END;
