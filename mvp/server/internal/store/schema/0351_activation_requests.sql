-- Two-person activation of write-enabled connections (deployment readiness
-- DR-10, design §4.4 and §9). Activating a revision whose write_mode is not
-- 'off' needs a second person: one holder of connections.activate requests,
-- a different one approves, and the approval applies the activation in the
-- same transaction (the `connection.activate` applier).
--
-- Tenant-owned like every table of 0001_tenancy.sql: tenant_id references
-- tenants(id), the unique constraint starts with tenant_id, and the guard
-- triggers refuse a reference to another tenant's connection or revision.
-- config_hash binds a request to the exact configuration it was made for: a
-- change of the revision makes the request stale and approval refuses it.
CREATE TABLE IF NOT EXISTS connection_activation_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  revision_id TEXT NOT NULL REFERENCES connection_revisions (id),
  config_hash TEXT NOT NULL,
  write_mode TEXT NOT NULL CHECK (write_mode IN ('dry_run','scoped')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','rejected','cancelled','expired')),
  requested_by_key TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_by_key TEXT,
  decided_by TEXT,
  decided_at TEXT,
  decision_note TEXT NOT NULL DEFAULT '',
  CHECK (status = 'pending' OR decided_at IS NOT NULL),
  CHECK (status <> 'applied' OR decided_by_key <> requested_by_key)
);
CREATE INDEX IF NOT EXISTS ix_activation_requests_conn ON connection_activation_requests (tenant_id, connection_id, requested_at);
-- at most one open request per revision
CREATE UNIQUE INDEX IF NOT EXISTS ux_activation_requests_open ON connection_activation_requests (tenant_id, revision_id) WHERE status = 'pending';

CREATE TRIGGER IF NOT EXISTS tg_connection_activation_requests_xtenant_ins BEFORE INSERT ON connection_activation_requests
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connection_activation_requests'); END;

CREATE TRIGGER IF NOT EXISTS tg_connection_activation_requests_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id, revision_id ON connection_activation_requests
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM connection_revisions p WHERE p.id = NEW.revision_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: connection_activation_requests'); END;
