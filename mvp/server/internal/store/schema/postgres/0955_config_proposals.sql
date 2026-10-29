-- Postgres variant of 0952_config_proposals.sql (issue #721). The composite foreign key stands in for the
-- cross-tenant triggers.
CREATE TABLE admin_change_proposals (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  change_id TEXT NOT NULL,
  client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 64),
  proposed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, change_id),
  FOREIGN KEY (tenant_id, change_id) REFERENCES admin_change_requests (tenant_id, id)
);
CREATE INDEX admin_change_proposals_client ON admin_change_proposals (tenant_id, client_id, proposed_at);
