-- Postgres variant of the dormant_people_days column of schema/0766_identity_rules.sql: how long an enabled account
-- may go without a sign-in before reconciliation (RF-07) reports it stale. Existing rows take the 90-day default.

-- +goose Up
ALTER TABLE identity_rules ADD COLUMN dormant_people_days BIGINT NOT NULL DEFAULT 90 CHECK (dormant_people_days BETWEEN 1 AND 3650);
