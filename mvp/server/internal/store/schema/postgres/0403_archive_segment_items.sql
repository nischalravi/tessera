-- Postgres dialect of schema/0403_archive_segment_items.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The cross-tenant trigger is a composite foreign key
-- (tenant_id, segment_id) -> archive_segments (tenant_id, id); the guards are one plpgsql function.

-- +goose Up

CREATE TABLE archive_segment_items (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  segment_id TEXT NOT NULL,
  item_id TEXT NOT NULL CHECK (length(item_id) BETWEEN 1 AND 64),
  PRIMARY KEY (tenant_id, segment_id, item_id),
  FOREIGN KEY (tenant_id, segment_id) REFERENCES archive_segments (tenant_id, id)
);

CREATE TRIGGER archive_segment_items_no_update BEFORE UPDATE ON archive_segment_items
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('archive_segment_items is append-only');
CREATE TRIGGER archive_segment_items_no_delete BEFORE DELETE ON archive_segment_items
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('archive_segment_items is append-only');
CREATE TRIGGER archive_segment_items_no_truncate BEFORE TRUNCATE ON archive_segment_items
	FOR EACH STATEMENT EXECUTE FUNCTION tessera_abort('archive_segment_items is append-only');

-- A delete of a request's event log or a campaign's frozen population passes only while a verified
-- segment of the right class for the row's tenant lists that request or campaign.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archived_item_delete() RETURNS trigger LANGUAGE plpgsql AS $fn$
DECLARE item TEXT; cls TEXT;
BEGIN
	IF TG_TABLE_NAME = 'access_request_events' THEN
		item := OLD.line_id;
		cls := 'requests';
	ELSE
		item := OLD.campaign_id::TEXT;
		cls := 'review_campaigns';
	END IF;
	IF EXISTS (SELECT 1 FROM archive_segments s JOIN archive_segment_items i ON i.tenant_id = s.tenant_id AND i.segment_id = s.id
			WHERE s.tenant_id = OLD.tenant_id AND s.class = cls AND s.status = 'verified' AND i.item_id = item) THEN
		RETURN OLD;
	END IF;
	RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$fn$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS access_request_events_no_delete ON access_request_events;
CREATE TRIGGER access_request_events_no_delete BEFORE DELETE ON access_request_events
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archived_item_delete();
DROP TRIGGER IF EXISTS review_populations_no_delete ON review_populations;
CREATE TRIGGER review_populations_no_delete BEFORE DELETE ON review_populations
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archived_item_delete();
DROP TRIGGER IF EXISTS review_population_rows_no_delete ON review_population_rows;
CREATE TRIGGER review_population_rows_no_delete BEFORE DELETE ON review_population_rows
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archived_item_delete();
DROP TRIGGER IF EXISTS review_auto_decisions_no_delete ON review_auto_decisions;
CREATE TRIGGER review_auto_decisions_no_delete BEFORE DELETE ON review_auto_decisions
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archived_item_delete();
