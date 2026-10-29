-- Restore of revoked access on a denial (issue #662, LP-6; design docs/design/least-privilege-loop.md sections 5.2
-- and 6.2). lp_denial_hooks holds, per tenant, the digest of the secret the customer's EventBridge API destination
-- presents (the secret itself is shown once, at creation). lp_denials records each denial event that named a
-- principal with a revoked grant: what was denied, when it arrived, what the loop did, and which revocation it
-- restored. The row's arrival time is where the 15-minute restore SLO starts.
--
-- Tenant-owned like 0001_tenancy.sql: tenant_id on every row, every unique index starts with it, every statement
-- binds it. revocation_id is not a foreign key: the history outlives a pruned revocation.
CREATE TABLE IF NOT EXISTS lp_denial_hooks (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  secret_sha256 TEXT NOT NULL CHECK (length(secret_sha256) = 64),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  rotated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id)
);

CREATE TABLE IF NOT EXISTS lp_denials (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('cloudtrail', 'idp')),
  event_id TEXT NOT NULL,                   -- the CloudTrail eventID (or the IdP's event id): a redelivery is a no-op
  principal_arn TEXT NOT NULL,
  action TEXT NOT NULL,                     -- in evaluator spelling, service:Action
  resource TEXT NOT NULL DEFAULT '',        -- the denied resource ARN when the event named one
  occurred_at TEXT,                         -- the event's own time, when it carried one
  arrived_at TEXT NOT NULL,                 -- when Tessera received it: the SLO clock
  outcome TEXT NOT NULL CHECK (outcome IN ('restore_requested', 'action_not_removed')),
  revocation_id TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS lp_denials_event ON lp_denials (tenant_id, source, event_id);
CREATE INDEX IF NOT EXISTS lp_denials_arrived ON lp_denials (tenant_id, arrived_at);
