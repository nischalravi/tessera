-- Postgres dialect of schema/0520_archive_verify_proof.sql (issue #401, reopened): the same recomputed
-- evidence, and a privilege boundary. A segment becomes verified only inside
-- tessera_archive_mark_verified, a SECURITY DEFINER function owned by the migration role (the table
-- owner); the trigger refuses the written -> verified transition for any other current_user, so the
-- application role (tessera_app) cannot UPDATE a forged segment to verified with plain SQL. The
-- function runs under the transaction's tenant and row-level security like the purge function does.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archive_verify() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
	IF OLD.status = 'written' AND NEW.status = 'verified' THEN
		IF current_user <> (SELECT t.tableowner FROM pg_tables t WHERE t.schemaname = current_schema() AND t.tablename = 'archive_segments') THEN
			RAISE EXCEPTION 'archive_segments: only tessera_archive_mark_verified verifies a segment' USING ERRCODE = 'insufficient_privilege';
		END IF;
		IF (NEW.class IN ('requests','review_campaigns') AND
				(SELECT count(*) FROM archive_segment_items i WHERE i.tenant_id = NEW.tenant_id AND i.segment_id = NEW.id) <> NEW.item_count)
			OR (NEW.class = 'audit' AND (
				NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_from AND e.hash = NEW.first_hash)
				OR NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_to AND e.hash = NEW.last_hash)
				OR NEW.item_count <> NEW.seq_to - NEW.seq_from + 1
				OR (SELECT count(*) FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq >= NEW.seq_from AND e.seq <= NEW.seq_to) <> NEW.seq_to - NEW.seq_from + 1
				OR EXISTS (SELECT 1 FROM audit_events e JOIN audit_events p ON p.tenant_id = e.tenant_id AND p.seq = e.seq - 1
					WHERE e.tenant_id = NEW.tenant_id AND e.seq > NEW.seq_from AND e.seq <= NEW.seq_to AND e.prev_hash <> p.hash))) THEN
			RAISE EXCEPTION 'archive_segments: nothing backs this verification' USING ERRCODE = 'integrity_constraint_violation';
		END IF;
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

-- Returns the segment id when it moved from written to verified, no row otherwise (the caller maps
-- that to ErrNotFound). The trigger above checks the evidence.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_archive_mark_verified(p_tenant TEXT, p_segment TEXT, p_now TEXT) RETURNS SETOF TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
	IF p_tenant IS NULL OR p_tenant <> NULLIF(current_setting('app.tenant_id', true), '') THEN
		RAISE EXCEPTION 'tessera_archive_mark_verified: not the transaction''s tenant' USING ERRCODE = 'insufficient_privilege';
	END IF;
	UPDATE archive_segments SET status = 'verified', verified_at = p_now
		WHERE tenant_id = p_tenant AND id = p_segment AND status = 'written';
	IF FOUND THEN
		RETURN NEXT p_segment;
	END IF;
END
$fn$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION tessera_archive_mark_verified(TEXT, TEXT, TEXT) FROM PUBLIC;
-- +goose StatementBegin
DO $grant$
BEGIN
	IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tessera_app') THEN
		GRANT EXECUTE ON FUNCTION tessera_archive_mark_verified(TEXT, TEXT, TEXT) TO tessera_app;
	END IF;
END
$grant$;
-- +goose StatementEnd
