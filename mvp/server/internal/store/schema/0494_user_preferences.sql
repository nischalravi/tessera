-- Per-user preferences (issue #298, "User preferences"): time zone, date
-- format, locale and the page to land on after sign-in. One row per signed-in
-- user; no row (or an empty value) means the default: the browser's time zone and
-- locale, ISO dates, the home page. The API validates the values: an IANA time
-- zone name, one of a fixed list of date formats and locales, and a landing path
-- from the UI's own list. A user changes only their own row.
--
-- Tenant-owned: guard triggers at the end refuse references to another tenant's rows.
CREATE TABLE IF NOT EXISTS user_preferences (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  time_zone TEXT NOT NULL DEFAULT '',
  date_format TEXT NOT NULL DEFAULT '',
  locale TEXT NOT NULL DEFAULT '',
  landing_page TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TRIGGER IF NOT EXISTS tg_user_preferences_xtenant_ins BEFORE INSERT ON user_preferences
WHEN EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.user_id AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: user_preferences'); END;

CREATE TRIGGER IF NOT EXISTS tg_user_preferences_xtenant_upd BEFORE UPDATE OF tenant_id, user_id ON user_preferences
WHEN EXISTS (SELECT 1 FROM platform_users u WHERE u.id = NEW.user_id AND u.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: user_preferences'); END;
