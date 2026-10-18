-- Privileges of the application role (Phase 0 PR14, design §13.8, §14.3).
--
-- The tables belong to the role that runs the migrations (tessera_owner). The
-- application connects as tessera_app: NOSUPERUSER, NOBYPASSRLS, not an owner
-- (README, "Postgres" has the CREATE ROLE statements). The role must exist
-- before the migrations run; if it does not, nothing is granted and the
-- application cannot read the tables, which fails closed. Re-run the
-- migrations (or this file) after creating it.
--
-- audit_events and audit_checkpoints are append-only for the application: no
-- UPDATE, DELETE or TRUNCATE, except the anchor_* columns of a checkpoint
-- (the anchor sink records where a checkpoint was stored). The plpgsql
-- triggers in 0004_audit.sql are the second layer.

-- +goose Up

-- +goose StatementBegin
DO $roles$
BEGIN
	IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tessera_app') THEN
		EXECUTE format('GRANT USAGE ON SCHEMA %I TO tessera_app', current_schema());
		EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO tessera_app', current_schema());
		EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO tessera_app', current_schema());
		REVOKE UPDATE, DELETE, TRUNCATE ON audit_events, audit_checkpoints FROM tessera_app;
		GRANT UPDATE (anchor_status, anchor_ref, anchored_at, anchor_attempts) ON audit_checkpoints TO tessera_app;
		-- the migration bookkeeping is the owner's alone
		EXECUTE format('REVOKE ALL ON %I.schema_migrations FROM tessera_app', current_schema());
	END IF;
END
$roles$;
-- +goose StatementEnd
