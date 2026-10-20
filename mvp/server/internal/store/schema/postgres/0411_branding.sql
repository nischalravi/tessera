-- Postgres dialect of schema/0411_branding.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). logo_data is BYTEA.

-- +goose Up

CREATE TABLE tenant_branding (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 80),
  primary_color TEXT NOT NULL CHECK (length(primary_color) = 7),
  on_primary_color TEXT NOT NULL CHECK (length(on_primary_color) = 7),
  logo_data BYTEA,
  logo_type TEXT CHECK (logo_type IN ('image/png','image/jpeg')),
  logo_width BIGINT,
  logo_height BIGINT,
  logo_sha256 TEXT,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK ((logo_data IS NULL) = (logo_type IS NULL))
);
