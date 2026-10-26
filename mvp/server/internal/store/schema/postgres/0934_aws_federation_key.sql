-- Postgres counterpart of the 'aws_federation' signing-key purpose added to
-- schema/0003_keys.sql (issue #676). SQLite rebuilds the table
-- (DB.upgradeSigningKeyPurposes); here the CHECK is replaced.

-- +goose Up

ALTER TABLE tenant_signing_keys DROP CONSTRAINT IF EXISTS tenant_signing_keys_purpose_check;
ALTER TABLE tenant_signing_keys ADD CONSTRAINT tenant_signing_keys_purpose_check
  CHECK (purpose IN ('access_token','idp_client_auth','aws_federation'));
