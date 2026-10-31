-- Postgres variant of schema/0961_policy_syncs.sql (issue #657, AC-11): merge sync of the policy repository. The composite
-- foreign key stands in for the cross-tenant triggers. This file also widens the admin_change_requests type CHECK to admit
-- policy.sync.apply (SQLite: 0008_admin_changes.sql and DB.upgradeAdminChangeTypes); the list is every type of
-- 0964_agent_scopes_change_type.sql and this one: a migration after this one that adds a type must add it here too.

-- +goose Up

ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke','groups.loader.save','retention.update','groups.folder.delete_recursive',
    'deletion_guard.update','siem.sink.filter','siem.sink.target','alerts.rule.loosen','breach.item.attest',
    'provisioning.write_back.enable','lp.settings.update','roles.bundle.apply','config.proposal','api_client.propose.grant',
    'lp.auto_policy.apply','jit.bundle.apply','sod.bundle.apply','agent_scopes.bundle.apply','policy.sync.apply'));

CREATE TABLE policy_syncs (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  repo TEXT NOT NULL CHECK (length(repo) <= 201),
  sha TEXT NOT NULL CHECK (length(sha) BETWEEN 40 AND 64),
  kind TEXT NOT NULL CHECK (kind IN ('sync', 'rollback')),
  rollback_from TEXT NOT NULL DEFAULT '' CHECK (length(rollback_from) <= 64),
  change_id TEXT NOT NULL,
  bundle_sha256 TEXT NOT NULL CHECK (length(bundle_sha256) <= 64),
  plan_sha256 TEXT NOT NULL CHECK (length(plan_sha256) <= 64),
  prediction TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  applied_at TEXT,
  active_key TEXT CHECK (active_key IS NULL OR length(active_key) <= 300),
  check_status TEXT NOT NULL DEFAULT 'pending' CHECK (check_status IN ('pending', 'verified', 'mismatch')),
  checked_at TEXT,
  check_detail TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, change_id),
  UNIQUE (tenant_id, active_key),
  FOREIGN KEY (tenant_id, change_id) REFERENCES admin_change_requests (tenant_id, id)
);
CREATE INDEX policy_syncs_applied ON policy_syncs (tenant_id, repo, applied_at);
