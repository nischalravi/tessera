-- Postgres dialect of schema/0402_archive_guards.sql: the delete guards of archived records.
--
-- audit_events: the application role has no DELETE on it (0900_roles.sql revokes it) and the
-- append-only trigger of 0004 stays in spirit; the only way to remove an event is
-- tessera_archive_purge_audit, a SECURITY DEFINER function that deletes the events of the
-- transaction's tenant up to a seq. The trigger below lets a delete through only for an event
-- inside a verified audit segment. The function checks app.tenant_id itself, so one tenant's
-- transaction never purges another's chain.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archived_delete() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
	IF TG_TABLE_NAME = 'audit_events' THEN
		IF EXISTS (SELECT 1 FROM archive_segments s
				WHERE s.tenant_id = OLD.tenant_id AND s.class = 'audit' AND s.status = 'verified'
					AND OLD.seq >= s.seq_from AND OLD.seq <= s.seq_to) THEN
			RETURN OLD;
		END IF;
		RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	-- the request event log, and the frozen review population of a campaign (0350)
	IF EXISTS (SELECT 1 FROM archive_segments s
			WHERE s.tenant_id = OLD.tenant_id AND s.status = 'verified'
				AND s.class = CASE TG_TABLE_NAME WHEN 'access_request_events' THEN 'requests' ELSE 'review_campaigns' END) THEN
		RETURN OLD;
	END IF;
	RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$fn$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archived_delete();
DROP TRIGGER IF EXISTS access_request_events_no_delete ON access_request_events;
CREATE TRIGGER access_request_events_no_delete BEFORE DELETE ON access_request_events
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archived_delete();
DROP TRIGGER IF EXISTS review_populations_no_delete ON review_populations;
CREATE TRIGGER review_populations_no_delete BEFORE DELETE ON review_populations
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archived_delete();
DROP TRIGGER IF EXISTS review_population_rows_no_delete ON review_population_rows;
CREATE TRIGGER review_population_rows_no_delete BEFORE DELETE ON review_population_rows
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archived_delete();
DROP TRIGGER IF EXISTS review_auto_decisions_no_delete ON review_auto_decisions;
CREATE TRIGGER review_auto_decisions_no_delete BEFORE DELETE ON review_auto_decisions
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archived_delete();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_archive_purge_audit(p_tenant TEXT, p_through BIGINT) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE n BIGINT;
BEGIN
	IF p_tenant IS NULL OR p_tenant <> NULLIF(current_setting('app.tenant_id', true), '') THEN
		RAISE EXCEPTION 'tessera_archive_purge_audit: not the transaction''s tenant' USING ERRCODE = 'insufficient_privilege';
	END IF;
	DELETE FROM audit_events WHERE tenant_id = p_tenant AND seq <= p_through;
	GET DIAGNOSTICS n = ROW_COUNT;
	RETURN n;
END
$fn$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION tessera_archive_purge_audit(TEXT, BIGINT) FROM PUBLIC;
-- +goose StatementBegin
DO $grant$
BEGIN
	IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tessera_app') THEN
		GRANT EXECUTE ON FUNCTION tessera_archive_purge_audit(TEXT, BIGINT) TO tessera_app;
	END IF;
END
$grant$;
-- +goose StatementEnd
