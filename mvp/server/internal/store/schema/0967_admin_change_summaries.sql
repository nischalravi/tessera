-- The one-line summary of an applied alert-channel change request as it read when it was applied (issue #977). A
-- summary is otherwise rebuilt from live state on every read, so after the change the "old" half of "old -> new" would
-- be the new value and a deleted channel would be shown by id only. Written in the apply transaction, before the change
-- is made; never holds a secret or a webhook URL (the summary builder never puts one in).
--
-- Tenant-owned: tenant_id on every row and first in the key. change_id references the request in the same tenant.
-- Postgres: migration 0979.
CREATE TABLE IF NOT EXISTS admin_change_summaries (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  change_id TEXT NOT NULL,
  summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 1000),
  PRIMARY KEY (tenant_id, change_id),
  FOREIGN KEY (tenant_id, change_id) REFERENCES admin_change_requests (tenant_id, id)
);

CREATE TRIGGER IF NOT EXISTS tg_admin_change_summaries_xtenant_ins BEFORE INSERT ON admin_change_summaries
WHEN NOT EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_change_summaries'); END;

CREATE TRIGGER IF NOT EXISTS tg_admin_change_summaries_xtenant_upd BEFORE UPDATE OF tenant_id, change_id ON admin_change_summaries
WHEN NOT EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_change_summaries'); END;
