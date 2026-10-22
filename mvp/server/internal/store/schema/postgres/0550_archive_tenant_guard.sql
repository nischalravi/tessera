-- Tenant guard of the archive SECURITY DEFINER functions (issue #436). The guard in 0530 read
--   p_tenant <> NULLIF(current_setting('app.tenant_id', true), '')
-- and when app.tenant_id is unset or empty the right-hand side is NULL, so the comparison is NULL and
-- the IF does not raise: outside a tenant transaction the definer (BYPASSRLS) ran the statements for
-- any p_tenant. This file redefines both functions to raise first when the setting is NULL or empty,
-- and compares with IS DISTINCT FROM so a NULL can never pass. Bodies are otherwise as in 0530;
-- CREATE OR REPLACE keeps the owner and the EXECUTE grants of 0520.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_archive_mark_verified(p_tenant TEXT, p_segment TEXT, p_now TEXT) RETURNS SETOF TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE cur TEXT := NULLIF(pg_catalog.current_setting('app.tenant_id', true), '');
BEGIN
	IF cur IS NULL OR p_tenant IS NULL OR p_tenant IS DISTINCT FROM cur THEN
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
DECLARE n BIGINT; s public.archive_segments%ROWTYPE; cur TEXT := NULLIF(pg_catalog.current_setting('app.tenant_id', true), '');
BEGIN
	IF cur IS NULL OR p_tenant IS NULL OR p_tenant IS DISTINCT FROM cur THEN
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
