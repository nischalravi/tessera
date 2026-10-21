-- Postgres dialect of schema/0510_archive_segment_guards.sql (issue #401): the same three guards as
-- plpgsql triggers, and tessera_archive_purge_audit takes a segment id instead of a seq, deleting only
-- the range of that one verified segment of the transaction's tenant.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archive_segment_insert() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
	IF NEW.status <> 'written' OR NEW.verified_at IS NOT NULL OR NEW.purged_at IS NOT NULL THEN
		RAISE EXCEPTION 'archive_segments are inserted as written' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS archive_segments_insert_written ON archive_segments;
CREATE TRIGGER archive_segments_insert_written BEFORE INSERT ON archive_segments
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archive_segment_insert();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archive_item_insert() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM archive_segments p WHERE p.id = NEW.segment_id AND p.tenant_id = NEW.tenant_id AND p.status = 'written') THEN
		RAISE EXCEPTION 'archive_segment_items: the segment is not open for items' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS archive_segment_items_parent_written ON archive_segment_items;
CREATE TRIGGER archive_segment_items_parent_written BEFORE INSERT ON archive_segment_items
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archive_item_insert();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archive_verify() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
	IF OLD.status = 'written' AND NEW.status = 'verified' THEN
		IF (NEW.class IN ('requests','review_campaigns') AND NOT EXISTS (SELECT 1 FROM archive_segment_items i WHERE i.tenant_id = NEW.tenant_id AND i.segment_id = NEW.id))
			OR (NEW.class = 'audit' AND (
				NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_from AND e.hash = NEW.first_hash)
				OR NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_to AND e.hash = NEW.last_hash))) THEN
			RAISE EXCEPTION 'archive_segments: nothing backs this verification' USING ERRCODE = 'integrity_constraint_violation';
		END IF;
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS archive_segments_verify_evidence ON archive_segments;
CREATE TRIGGER archive_segments_verify_evidence BEFORE UPDATE OF status ON archive_segments
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archive_verify();

-- The purge function names the segment. The old (tenant, through) form is dropped.
DROP FUNCTION IF EXISTS tessera_archive_purge_audit(TEXT, BIGINT);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_archive_purge_audit(p_tenant TEXT, p_segment TEXT) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE n BIGINT; s archive_segments%ROWTYPE;
BEGIN
	IF p_tenant IS NULL OR p_tenant <> NULLIF(current_setting('app.tenant_id', true), '') THEN
		RAISE EXCEPTION 'tessera_archive_purge_audit: not the transaction''s tenant' USING ERRCODE = 'insufficient_privilege';
	END IF;
	SELECT * INTO s FROM archive_segments WHERE tenant_id = p_tenant AND id = p_segment AND class = 'audit' AND status = 'verified';
	IF NOT FOUND THEN
		RAISE EXCEPTION 'tessera_archive_purge_audit: no verified audit segment %', p_segment USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	DELETE FROM audit_events WHERE tenant_id = p_tenant AND seq >= s.seq_from AND seq <= s.seq_to;
	GET DIAGNOSTICS n = ROW_COUNT;
	RETURN n;
END
$fn$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION tessera_archive_purge_audit(TEXT, TEXT) FROM PUBLIC;
-- +goose StatementBegin
DO $grant$
BEGIN
	IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tessera_app') THEN
		GRANT EXECUTE ON FUNCTION tessera_archive_purge_audit(TEXT, TEXT) TO tessera_app;
	END IF;
END
$grant$;
-- +goose StatementEnd
