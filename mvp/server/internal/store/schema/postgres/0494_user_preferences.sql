-- Postgres dialect of schema/0494_user_preferences.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id).

-- +goose Up

CREATE TABLE user_preferences (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT NOT NULL,
  time_zone TEXT NOT NULL DEFAULT '',
  date_format TEXT NOT NULL DEFAULT '',
  locale TEXT NOT NULL DEFAULT '',
  landing_page TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES platform_users (tenant_id, id)
);
