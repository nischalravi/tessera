-- Postgres counterpart of the 'test' login purpose added to
-- schema/0005_auth.sql: a login transaction may be the test sign-in of a
-- pending IdP connection (design §15.2). SQLite drops and recreates the
-- table (DB.upgradeLoginTxnPurpose); here the CHECK is replaced.

-- +goose Up

ALTER TABLE login_transactions DROP CONSTRAINT IF EXISTS login_transactions_purpose_check;
ALTER TABLE login_transactions ADD CONSTRAINT login_transactions_purpose_check
  CHECK (purpose IN ('login','step_up','device_approval','bootstrap','test'));
