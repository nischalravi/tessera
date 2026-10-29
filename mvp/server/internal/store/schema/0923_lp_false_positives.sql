-- False positives of the least-privilege loop (issue #663, LP-7; design docs/design/least-privilege-loop.md sections
-- 5.2, 9 and 10). A revocation is labelled a false positive when the access turned out to be needed: a JIT request
-- for it in the revoke window, or a restore (a denial, the owner, an admin). One row per revocation. The calibration
-- (restores divided by revocations, per confidence level, over 60 days) counts these rows.
--
-- Tenant-owned like 0001_tenancy.sql: tenant_id on every row, every unique index starts with it, every statement
-- binds it. ref is the JIT request id (or the restore trigger's own reference); it is not a foreign key.
CREATE TABLE IF NOT EXISTS lp_false_positives (
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
CREATE UNIQUE INDEX IF NOT EXISTS lp_false_positives_rev ON lp_false_positives (tenant_id, revocation_id);
CREATE INDEX IF NOT EXISTS lp_false_positives_created ON lp_false_positives (tenant_id, confidence, created_at);

CREATE TRIGGER IF NOT EXISTS tg_lp_false_positives_xtenant_ins BEFORE INSERT ON lp_false_positives
WHEN NOT EXISTS (SELECT 1 FROM lp_revocations p WHERE p.id = NEW.revocation_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: lp_false_positives'); END;

CREATE TRIGGER IF NOT EXISTS tg_lp_false_positives_xtenant_upd BEFORE UPDATE OF tenant_id, revocation_id ON lp_false_positives
WHEN NOT EXISTS (SELECT 1 FROM lp_revocations p WHERE p.id = NEW.revocation_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: lp_false_positives'); END;
