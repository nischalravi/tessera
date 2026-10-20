-- Postgres dialect of schema/0400_retention.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres).
--
-- It also widens the admin_change_requests type CHECK to admit retention.update (numbered after
-- 0377_group_loaders.sql, which sets the same CHECK; SQLite changes the CHECK in
-- 0008_admin_changes.sql). The list is every type of 0008 and later: a migration between 0377 and
-- this one that adds a type must add it here too.

-- +goose Up

ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke','groups.loader.save','retention.update'));

CREATE TABLE retention_policies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  class TEXT NOT NULL CHECK (class IN ('audit','review_campaigns','requests','job_runs','notifications')),
  days BIGINT NOT NULL CHECK (days BETWEEN 1 AND 36500),
  updated_at TEXT NOT NULL,
  updated_by TEXT,
  PRIMARY KEY (tenant_id, class)
);
