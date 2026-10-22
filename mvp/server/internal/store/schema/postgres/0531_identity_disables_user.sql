-- Postgres dialect of schema/0531_identity_disables_user.sql (issue #425).

-- +goose Up

ALTER TABLE identity_disables ADD COLUMN disabled_by_user_id TEXT;
