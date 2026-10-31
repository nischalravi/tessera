-- Prediction-check findings of a merge sync (issue #657, AC-11): one row for each place where what the blast-radius
-- preview predicted differs from what was observed after the apply (a permission that should have been gained and was not,
-- a policy violation that appeared or did not, ...). predicted and observed are short texts and detail the JSON of the
-- difference. Rows are written in the transaction of the apply and never changed or deleted.
--
-- Tenant-owned; guard triggers refuse a sync of another tenant. Postgres: migration 0970.
CREATE TABLE IF NOT EXISTS policy_sync_findings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  sync_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
  subject TEXT NOT NULL CHECK (length(subject) <= 400),
  predicted TEXT NOT NULL CHECK (length(predicted) <= 400),
  observed TEXT NOT NULL CHECK (length(observed) <= 400),
  raised_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, sync_id) REFERENCES policy_syncs (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS policy_sync_findings_sync ON policy_sync_findings (tenant_id, sync_id, raised_at);

CREATE TRIGGER IF NOT EXISTS tg_policy_sync_findings_xtenant_ins BEFORE INSERT ON policy_sync_findings
WHEN NOT EXISTS (SELECT 1 FROM policy_syncs p WHERE p.id = NEW.sync_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: policy_sync_findings'); END;

CREATE TRIGGER IF NOT EXISTS tg_policy_sync_findings_xtenant_upd BEFORE UPDATE OF tenant_id, sync_id ON policy_sync_findings
WHEN NOT EXISTS (SELECT 1 FROM policy_syncs p WHERE p.id = NEW.sync_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: policy_sync_findings'); END;

CREATE TRIGGER IF NOT EXISTS tg_policy_sync_findings_no_update BEFORE UPDATE ON policy_sync_findings
BEGIN SELECT RAISE(ABORT, 'policy_sync_findings is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_policy_sync_findings_no_delete BEFORE DELETE ON policy_sync_findings
BEGIN SELECT RAISE(ABORT, 'policy_sync_findings is append-only'); END;
