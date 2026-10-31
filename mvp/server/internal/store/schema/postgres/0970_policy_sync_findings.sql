-- Postgres variant of schema/0962_policy_sync_findings.sql (issue #657, AC-11). The composite foreign key stands in for
-- the cross-tenant triggers.

-- +goose Up

CREATE TABLE policy_sync_findings (
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
CREATE INDEX policy_sync_findings_sync ON policy_sync_findings (tenant_id, sync_id, raised_at);

CREATE TRIGGER policy_sync_findings_no_update BEFORE UPDATE ON policy_sync_findings
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('policy_sync_findings is append-only');

CREATE TRIGGER policy_sync_findings_no_delete BEFORE DELETE ON policy_sync_findings
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('policy_sync_findings is append-only');
