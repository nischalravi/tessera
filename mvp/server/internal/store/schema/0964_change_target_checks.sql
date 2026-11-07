-- The approver's "check this URL" attempts on a proposal that seals a URL (issue #886). An approver submits the URL they
-- expect and the server answers only match / no-match against the keyed fingerprint of the sealed one; each attempt is one
-- row here so the number of tries per proposal and per approver is bounded (a guessing oracle for the sealed URL is the
-- risk). fp is the request-bound keyed fingerprint of the SUBMITTED url (16 hex characters) and sealed_fp a per-tenant keyed
-- fingerprint of the SEALED url, the key the tries are counted by across requests (never returned); neither is a URL.
--
-- The same table charges the proposals that seal a URL for an EXISTING channel or sink (a guessed URL would otherwise be
-- tested against the live one by whether the proposal reads as unchanged): one row per filing, sealed_fp the keyed
-- counter key of the live OBJECT, checked_by the client, flag the server-only comparison (same / path / moved) and live_fp
-- the keyed fingerprint of the live URL when it was filed (so a later change of the object reads as stale). Neither is returned
-- to the proposer or to a reader without the approve permission and a fresh step-up.
--
-- Tenant-owned: tenant_id on every row and first in every key. change_id references the request in the same tenant.
-- Postgres: migration 0972.
CREATE TABLE IF NOT EXISTS admin_change_target_checks (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,
  change_id TEXT NOT NULL,
  checked_by TEXT NOT NULL CHECK (length(checked_by) BETWEEN 1 AND 64),
  checked_at TEXT NOT NULL,
  fp TEXT NOT NULL CHECK (length(fp) BETWEEN 1 AND 64),
  sealed_fp TEXT NOT NULL CHECK (length(sealed_fp) BETWEEN 1 AND 64),
  flag TEXT NOT NULL DEFAULT '' CHECK (length(flag) <= 20),
  live_fp TEXT NOT NULL DEFAULT '' CHECK (length(live_fp) <= 64),
  matched INTEGER NOT NULL CHECK (matched IN (0, 1)),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, change_id) REFERENCES admin_change_requests (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS admin_change_target_checks_value ON admin_change_target_checks (tenant_id, sealed_fp, checked_at);
CREATE INDEX IF NOT EXISTS admin_change_target_checks_who ON admin_change_target_checks (tenant_id, checked_by, checked_at);

CREATE TRIGGER IF NOT EXISTS tg_admin_change_target_checks_xtenant_ins BEFORE INSERT ON admin_change_target_checks
WHEN NOT EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_change_target_checks'); END;

CREATE TRIGGER IF NOT EXISTS tg_admin_change_target_checks_xtenant_upd BEFORE UPDATE OF tenant_id, change_id ON admin_change_target_checks
WHEN NOT EXISTS (SELECT 1 FROM admin_change_requests p WHERE p.id = NEW.change_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: admin_change_target_checks'); END;
