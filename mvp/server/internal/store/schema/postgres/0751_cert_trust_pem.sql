-- Postgres counterpart of the trust_pem column added to schema/0410_certificates.sql (issue #498): the CA
-- certificates a connection's target must chain to, kept with its mutual-TLS client certificate. SQLite adds the
-- column in DB.upgradeCertTrust.

-- +goose Up

ALTER TABLE tenant_certificates ADD COLUMN IF NOT EXISTS trust_pem TEXT NOT NULL DEFAULT '';
