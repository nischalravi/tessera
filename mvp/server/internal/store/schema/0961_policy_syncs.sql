-- Merge sync of the policy repository (issue #657, AC-11): applying the policy bundle at a commit of the default branch,
-- recording the commit, and checking afterwards that what was predicted is what happened.
--
-- policy_syncs: one row per sync request, made in the transaction that files its admin change request (type
-- policy.sync.apply, always two admins). kind is sync (the bundle at sha) or rollback (the bundle at an earlier commit
-- Tessera applied before; sha is that commit and rollback_from the commit it was last synced to). prediction is the JSON
-- of the blast-radius prediction the approver reviewed (internal/syncverify). applied_at is set by the apply, in the
-- same transaction as the writes, together with check_status (verified; partial when the comparison could not be complete; or mismatch with findings in
-- policy_sync_findings) and its JSON detail. active_key is "<repo>|<sha>|<kind>" while the request is open or applied
-- and NULL once it ended without applying, so one commit is filed once (idempotent per tenant, repo and sha) and a
-- rejected request can be filed again. The last synced commit of a repository is its newest applied row.
--
-- Tenant-owned: tenant_id on every row and first in every key; guard triggers refuse a change request of another
-- tenant. Postgres: migration 0969.
CREATE TABLE IF NOT EXISTS policy_syncs (
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
  check_status TEXT NOT NULL DEFAULT 'pending' CHECK (check_status IN ('pending', 'verified', 'partial', 'mismatch')),
  checked_at TEXT,
  check_detail TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, change_id),
  UNIQUE (tenant_id, active_key),
  FOREIGN KEY (tenant_id, change_id) REFERENCES admin_change_requests (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS policy_syncs_applied ON policy_syncs (tenant_id, repo, applied_at);

CREATE TRIGGER IF NOT EXISTS tg_policy_syncs_xtenant_ins BEFORE INSERT ON policy_syncs
WHEN NOT EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: policy_syncs'); END;

CREATE TRIGGER IF NOT EXISTS tg_policy_syncs_xtenant_upd BEFORE UPDATE OF tenant_id, change_id ON policy_syncs
WHEN NOT EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: policy_syncs'); END;
