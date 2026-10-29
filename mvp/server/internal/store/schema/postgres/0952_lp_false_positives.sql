-- Postgres variant of 0923_lp_false_positives.sql (issue #663, LP-7). The composite foreign key stands in for the
-- cross-tenant triggers.
CREATE TABLE lp_false_positives (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  revocation_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('jit', 'denial', 'owner', 'admin', 'undo_run')),
  ref TEXT NOT NULL DEFAULT '',
  principal_arn TEXT NOT NULL,
  policy_arn TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('high', 'medium')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, revocation_id) REFERENCES lp_revocations (tenant_id, id)
);
CREATE UNIQUE INDEX lp_false_positives_rev ON lp_false_positives (tenant_id, revocation_id);
CREATE INDEX lp_false_positives_created ON lp_false_positives (tenant_id, confidence, created_at);
