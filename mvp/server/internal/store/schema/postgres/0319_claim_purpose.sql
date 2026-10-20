-- Guest claim (issue #69) on databases that already ran 0005 and 0227: a login
-- transaction may carry the 'claim' purpose, and an intake record may be
-- 'expired' and keep the claimant's account answer and claim time. Fresh
-- databases get the same result from these files plus this one; the SQLite
-- counterparts are edited in place (schema/0005_auth.sql, schema/0227_sponsorships.sql).

-- +goose Up

ALTER TABLE login_transactions DROP CONSTRAINT IF EXISTS login_transactions_purpose_check;
ALTER TABLE login_transactions ADD CONSTRAINT login_transactions_purpose_check
  CHECK (purpose IN ('login','step_up','device_approval','bootstrap','test','claim'));

ALTER TABLE intake_records DROP CONSTRAINT IF EXISTS intake_records_invitation_status_check;
ALTER TABLE intake_records ADD CONSTRAINT intake_records_invitation_status_check
  CHECK (invitation_status IN ('ready','sent','claimed','revoked','expired'));
-- the claimant's own statement at the claim page's "do you already have an
-- account?" question (GU-6): recorded for the review queue, never used to link (K3)
ALTER TABLE intake_records ADD COLUMN IF NOT EXISTS existing_account TEXT CHECK (existing_account IN ('yes','no'));
ALTER TABLE intake_records ADD COLUMN IF NOT EXISTS existing_account_at TEXT;
ALTER TABLE intake_records ADD COLUMN IF NOT EXISTS claimed_at TEXT;
