-- Postgres dialect of schema/0532_attestation_user.sql (issue #425).

-- +goose Up

ALTER TABLE readiness_attestations ADD COLUMN actor_user_id TEXT;
