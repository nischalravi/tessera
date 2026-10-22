-- Who deleted a group, when and why (schema/0280_groups.sql has the columns for SQLite; an older SQLite
-- database gets them in upgradeUserIDColumns). Set by a soft delete, cleared by a restore. No table is added.

-- +goose Up

ALTER TABLE grp_groups ADD COLUMN IF NOT EXISTS deleted_by_user_id TEXT;
ALTER TABLE grp_groups ADD COLUMN IF NOT EXISTS deleted_by_display TEXT;
ALTER TABLE grp_groups ADD COLUMN IF NOT EXISTS deleted_at TEXT;
ALTER TABLE grp_groups ADD COLUMN IF NOT EXISTS deleted_reason TEXT;
ALTER TABLE grp_groups ADD COLUMN IF NOT EXISTS deleted_with_folder TEXT;
