-- Postgres only (schema/postgres/0530_definer_search_path.sql, issue #424): pg_temp shadowing of the
-- SECURITY DEFINER functions and archive guards. SQLite has no functions, no search_path and no
-- role boundary, so there is nothing to change; this file only keeps the two schema directories
-- numbered alike.
SELECT 1;
