-- Config proposals by machine clients (issue #721). A machine client holding the config.propose scope files a
-- config.proposal change request; the request itself is the ordinary admin_change_requests row (requested by the
-- client's owner, so the owner can never approve it either), and this row names the client that proposed it, so every
-- transition is audited with the client id and the client can poll only its own proposals.
--
-- Tenant-owned like 0001_tenancy.sql: tenant_id on every row, every statement binds it. client_id is the OAuth client
-- id (not a foreign key: a revoked client's proposals keep their record).
CREATE TABLE IF NOT EXISTS admin_change_proposals (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  change_id TEXT NOT NULL,
  client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 64),
  proposed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, change_id),
  FOREIGN KEY (tenant_id, change_id) REFERENCES admin_change_requests (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS admin_change_proposals_client ON admin_change_proposals (tenant_id, client_id, proposed_at);

CREATE TRIGGER IF NOT EXISTS tg_admin_change_proposals_xtenant_ins BEFORE INSERT ON admin_change_proposals
WHEN NOT EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_change_proposals'); END;

CREATE TRIGGER IF NOT EXISTS tg_admin_change_proposals_xtenant_upd BEFORE UPDATE OF tenant_id, change_id ON admin_change_proposals
WHEN NOT EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_change_proposals'); END;
