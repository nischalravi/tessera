-- Hardening of the SECURITY DEFINER functions and archive guards (issue #424). Postgres searches
-- pg_temp first for relations unless search_path names it, also inside a SECURITY DEFINER function,
-- and tessera_app could CREATE TEMPORARY tables. A temp table named archive_segments or audit_events
-- could therefore stand in for the real one: a forged segment "verified", or a purge of events with no
-- segment behind it. This file:
--   * pins SET search_path = pg_catalog, public, pg_temp (pg_temp last) on every SECURITY DEFINER
--     function and on the archive guards, and schema-qualifies every relation in them;
--   * finds the table owner in the verify guard through TG_RELID / pg_class.relowner (the old
--     current_schema() lookup gave NULL when the caller's search_path pointed elsewhere, and
--     current_user <> NULL does not raise), compared with IS DISTINCT FROM so NULL cannot pass;
--   * revokes TEMPORARY on the database from PUBLIC and tessera_app.
-- The function bodies of 0510/0520 are otherwise unchanged. It does not prove that the archive object
-- exists (README, "What the database boundary is, and is not").

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archive_segment_insert() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $fn$
BEGIN
	IF NEW.status <> 'written' OR NEW.verified_at IS NOT NULL OR NEW.purged_at IS NOT NULL THEN
		RAISE EXCEPTION 'archive_segments are inserted as written' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archive_item_insert() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $fn$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM public.archive_segments p WHERE p.id = NEW.segment_id AND p.tenant_id = NEW.tenant_id AND p.status = 'written') THEN
		RAISE EXCEPTION 'archive_segment_items: the segment is not open for items' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archive_verify() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $fn$
BEGIN
	IF OLD.status = 'written' AND NEW.status = 'verified' THEN
		IF current_user IS DISTINCT FROM (SELECT pg_catalog.pg_get_userbyid(c.relowner) FROM pg_catalog.pg_class c WHERE c.oid = TG_RELID) THEN
			RAISE EXCEPTION 'archive_segments: only tessera_archive_mark_verified verifies a segment' USING ERRCODE = 'insufficient_privilege';
		END IF;
		IF (NEW.class IN ('requests','review_campaigns') AND
				(SELECT count(*) FROM public.archive_segment_items i WHERE i.tenant_id = NEW.tenant_id AND i.segment_id = NEW.id) <> NEW.item_count)
			OR (NEW.class = 'audit' AND (
				NOT EXISTS (SELECT 1 FROM public.audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_from AND e.hash = NEW.first_hash)
				OR NOT EXISTS (SELECT 1 FROM public.audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_to AND e.hash = NEW.last_hash)
				OR NEW.item_count <> NEW.seq_to - NEW.seq_from + 1
				OR (SELECT count(*) FROM public.audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq >= NEW.seq_from AND e.seq <= NEW.seq_to) <> NEW.seq_to - NEW.seq_from + 1
				OR EXISTS (SELECT 1 FROM public.audit_events e JOIN public.audit_events p ON p.tenant_id = e.tenant_id AND p.seq = e.seq - 1
					WHERE e.tenant_id = NEW.tenant_id AND e.seq > NEW.seq_from AND e.seq <= NEW.seq_to AND e.prev_hash <> p.hash))) THEN
			RAISE EXCEPTION 'archive_segments: nothing backs this verification' USING ERRCODE = 'integrity_constraint_violation';
		END IF;
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archived_delete() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $fn$
BEGIN
	IF TG_TABLE_NAME = 'audit_events' THEN
		IF EXISTS (SELECT 1 FROM public.archive_segments s
				WHERE s.tenant_id = OLD.tenant_id AND s.class = 'audit' AND s.status = 'verified'
					AND OLD.seq >= s.seq_from AND OLD.seq <= s.seq_to) THEN
			RETURN OLD;
		END IF;
		RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_archive_mark_verified(p_tenant TEXT, p_segment TEXT, p_now TEXT) RETURNS SETOF TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $fn$
BEGIN
	IF p_tenant IS NULL OR p_tenant <> NULLIF(pg_catalog.current_setting('app.tenant_id', true), '') THEN
		RAISE EXCEPTION 'tessera_archive_mark_verified: not the transaction''s tenant' USING ERRCODE = 'insufficient_privilege';
	END IF;
	UPDATE public.archive_segments SET status = 'verified', verified_at = p_now
		WHERE tenant_id = p_tenant AND id = p_segment AND status = 'written';
	IF FOUND THEN
		RETURN NEXT p_segment;
	END IF;
END
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_archive_purge_audit(p_tenant TEXT, p_segment TEXT) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE n BIGINT; s public.archive_segments%ROWTYPE;
BEGIN
	IF p_tenant IS NULL OR p_tenant <> NULLIF(pg_catalog.current_setting('app.tenant_id', true), '') THEN
		RAISE EXCEPTION 'tessera_archive_purge_audit: not the transaction''s tenant' USING ERRCODE = 'insufficient_privilege';
	END IF;
	SELECT * INTO s FROM public.archive_segments WHERE tenant_id = p_tenant AND id = p_segment AND class = 'audit' AND status = 'verified';
	IF NOT FOUND THEN
		RAISE EXCEPTION 'tessera_archive_purge_audit: no verified audit segment %', p_segment USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	DELETE FROM public.audit_events WHERE tenant_id = p_tenant AND seq >= s.seq_from AND seq <= s.seq_to;
	GET DIAGNOSTICS n = ROW_COUNT;
	RETURN n;
END
$fn$;
-- +goose StatementEnd

-- The other SECURITY DEFINER functions (graph node keys, soft references, group and SoD guards) keep
-- their bodies; pg_temp goes last in their search_path so a temp table cannot stand in for a real one.
ALTER FUNCTION tessera_node_key_crosses(text, text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION tessera_guard_soft_ref() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION tessera_guard_grp_alias() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION tessera_guard_grp_object() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION tessera_guard_grp_attr_owner() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION tessera_guard_grp_rule() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION tessera_guard_grp_owner() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION tessera_guard_sod_versions() SET search_path = pg_catalog, public, pg_temp;

-- No temporary tables: the application creates none, and a session-local table is what shadows a real
-- one. Revoking needs the database owner (or a superuser); for any other migration role the statement
-- changes nothing and the DBA runs it (README, "Postgres").
-- +goose StatementBegin
DO $temp$
BEGIN
	EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
	IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tessera_app') THEN
		EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM tessera_app', current_database());
	END IF;
END
$temp$;
-- +goose StatementEnd
