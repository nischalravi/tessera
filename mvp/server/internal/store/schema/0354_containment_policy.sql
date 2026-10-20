-- Containment of AWS IAM Identity Center users (issue #114, review of PR #222):
-- the Deny service control policy is one shared document that several workers
-- (SSF events, manual contain, the retry sweeper) edit by read-modify-write.
--
-- containment_policy_leases: one row per (tenant, policy id) while a worker
-- holds the right to edit that policy. A lease expires on its own (expires_at)
-- so a crashed worker never blocks the policy for good. The holder is a random
-- token; only the holder releases it.
--
-- containment_policy_denials: every user id Tessera has put (state 'pending',
-- before the write) or has put and verified (state 'active') in a policy. A
-- worker merges all of them into the policy, so an entry another worker lost
-- to a concurrent write comes back. A row older than the 12 hour hold is
-- dropped: the policy's owner may remove the entry by hand after that.
--
-- Tenant-owned like 0001_tenancy.sql. Neither table references another
-- tenant-owned row, so there is nothing for a guard trigger to refuse.
CREATE TABLE IF NOT EXISTS containment_policy_leases (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  policy_id TEXT NOT NULL,
  holder TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, policy_id)
);

CREATE TABLE IF NOT EXISTS containment_policy_denials (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  policy_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','active')),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, policy_id, user_id)
);
