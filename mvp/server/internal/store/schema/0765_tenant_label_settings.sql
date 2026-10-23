-- Admin > Branding & labels: the words and language a tenant's people see, and
-- whether emails carry the logo. One row per tenant; no row means the defaults
-- (no renamed objects, the browser's language, a plain-text name in emails).
--
-- default_language is a BCP 47 tag from the list the API accepts ('' follows the
-- browser): it is the locale the UI formats dates and numbers with for a person
-- who chose none of their own. labels is a JSON object of renamed terms
-- ({"entitlement": "permission set"}); the API accepts only the known terms and
-- short plain-text values, so the object never holds markup. email_logo, when 1,
-- makes emails carry the tenant's logo (an HTML part that links the public logo
-- URL) next to the plain-text part.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS tenant_label_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  default_language TEXT NOT NULL DEFAULT '' CHECK (length(default_language) <= 10),
  email_logo INTEGER NOT NULL DEFAULT 0 CHECK (email_logo IN (0, 1)),
  labels TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(labels)),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
