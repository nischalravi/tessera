-- Admin > Branding: the name, colours and logo a tenant shows on its sign-in
-- page, the guest claim pages and in emails. One row per tenant.
--
-- display_name is the product name shown where "Tessera" would be.
-- primary_color is the button background and on_primary_color its text, both
-- #rrggbb; the API refuses a pair below WCAG AA (4.5:1) so a stored pair is
-- always readable. The logo is a raster image only (PNG or JPEG, never SVG):
-- logo_data holds the bytes, logo_type the content type it is served with,
-- logo_width and logo_height the checked dimensions and logo_sha256 its ETag.
-- The pages that show it are public, so nothing here is secret.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS tenant_branding (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 80),
  primary_color TEXT NOT NULL CHECK (length(primary_color) = 7),
  on_primary_color TEXT NOT NULL CHECK (length(on_primary_color) = 7),
  logo_data BLOB,
  logo_type TEXT CHECK (logo_type IN ('image/png','image/jpeg')),
  logo_width INTEGER,
  logo_height INTEGER,
  logo_sha256 TEXT,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK ((logo_data IS NULL) = (logo_type IS NULL))
);
