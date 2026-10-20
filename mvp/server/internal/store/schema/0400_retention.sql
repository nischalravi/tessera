-- Log retention settings (issue #298): how many days each data class stays
-- online before the archival job (internal/archive) seals it into an archive
-- segment (0401). One row per tenant and class; a class with no row uses the
-- default in internal/retention. The floors (minimum days) are enforced in Go,
-- on the change request that sets them, so a floor can be raised without a
-- migration; the CHECK only keeps the value sane.
--
-- Rows change only through an applied admin change request (type
-- retention.update, two people and step-up), which audits the change in the
-- same transaction; updated_by is that request's id.
CREATE TABLE IF NOT EXISTS retention_policies (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  class TEXT NOT NULL CHECK (class IN ('audit','review_campaigns','requests','job_runs','notifications')),
  days INTEGER NOT NULL CHECK (days BETWEEN 1 AND 36500),
  updated_at TEXT NOT NULL,
  updated_by TEXT,
  PRIMARY KEY (tenant_id, class)
);
