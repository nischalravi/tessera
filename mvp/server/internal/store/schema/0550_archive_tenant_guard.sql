-- Postgres only (schema/postgres/0550_archive_tenant_guard.sql, issue #436): the tenant guard of the
-- archive SECURITY DEFINER functions raises when app.tenant_id is unset. SQLite has no functions and
-- no role boundary, so there is nothing to change; this file only keeps the two schema directories
-- numbered alike.
SELECT 1;
