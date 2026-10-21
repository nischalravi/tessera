-- Which records an archive segment holds (issue #298), for the classes whose delete guard is per
-- record: item_id is the request id (class 'requests') or the campaign id (class
-- 'review_campaigns'). The archival job writes the rows in the transaction that catalogues the
-- segment. Append-only.
--
-- The delete guards of the append-only tables of those records (the request event log and the
-- frozen review population, 0205 and 0350) allow a delete only while a VERIFIED segment of the right
-- class for the same tenant lists the row's request or campaign here. A segment left verified by a
-- crash before its purge therefore unlocks only the records it holds, never others.
--
-- The triggers are dropped and created again on every start, after 0205 and 0350 created theirs.
CREATE TABLE IF NOT EXISTS archive_segment_items (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  segment_id TEXT NOT NULL REFERENCES archive_segments (id),
  item_id TEXT NOT NULL CHECK (length(item_id) BETWEEN 1 AND 64),
  PRIMARY KEY (tenant_id, segment_id, item_id)
);

CREATE TRIGGER IF NOT EXISTS archive_segment_items_no_update BEFORE UPDATE ON archive_segment_items
BEGIN SELECT RAISE(ABORT, 'archive_segment_items is append-only'); END;
CREATE TRIGGER IF NOT EXISTS archive_segment_items_no_delete BEFORE DELETE ON archive_segment_items
BEGIN SELECT RAISE(ABORT, 'archive_segment_items is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tg_archive_segment_items_xtenant_ins BEFORE INSERT ON archive_segment_items
WHEN NOT EXISTS (SELECT 1 FROM archive_segments p WHERE p.id = NEW.segment_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: archive_segment_items'); END;
CREATE TRIGGER IF NOT EXISTS tg_archive_segment_items_xtenant_upd BEFORE UPDATE OF tenant_id, segment_id ON archive_segment_items
WHEN NOT EXISTS (SELECT 1 FROM archive_segments p WHERE p.id = NEW.segment_id AND p.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: archive_segment_items'); END;

DROP TRIGGER IF EXISTS tg_access_request_events_no_delete;
CREATE TRIGGER tg_access_request_events_no_delete BEFORE DELETE ON access_request_events
WHEN NOT EXISTS (SELECT 1 FROM archive_segments s JOIN archive_segment_items i ON i.tenant_id = s.tenant_id AND i.segment_id = s.id
	WHERE s.tenant_id = OLD.tenant_id AND s.class = 'requests' AND s.status = 'verified' AND i.item_id = OLD.line_id)
BEGIN SELECT RAISE(ABORT, 'access_request_events is append-only'); END;

DROP TRIGGER IF EXISTS review_populations_no_delete;
CREATE TRIGGER review_populations_no_delete BEFORE DELETE ON review_populations
WHEN NOT EXISTS (SELECT 1 FROM archive_segments s JOIN archive_segment_items i ON i.tenant_id = s.tenant_id AND i.segment_id = s.id
	WHERE s.tenant_id = OLD.tenant_id AND s.class = 'review_campaigns' AND s.status = 'verified' AND i.item_id = CAST(OLD.campaign_id AS TEXT))
BEGIN SELECT RAISE(ABORT, 'review_populations is immutable'); END;

DROP TRIGGER IF EXISTS review_population_rows_no_delete;
CREATE TRIGGER review_population_rows_no_delete BEFORE DELETE ON review_population_rows
WHEN NOT EXISTS (SELECT 1 FROM archive_segments s JOIN archive_segment_items i ON i.tenant_id = s.tenant_id AND i.segment_id = s.id
	WHERE s.tenant_id = OLD.tenant_id AND s.class = 'review_campaigns' AND s.status = 'verified' AND i.item_id = CAST(OLD.campaign_id AS TEXT))
BEGIN SELECT RAISE(ABORT, 'review_population_rows is immutable'); END;

DROP TRIGGER IF EXISTS review_auto_decisions_no_delete;
CREATE TRIGGER review_auto_decisions_no_delete BEFORE DELETE ON review_auto_decisions
WHEN NOT EXISTS (SELECT 1 FROM archive_segments s JOIN archive_segment_items i ON i.tenant_id = s.tenant_id AND i.segment_id = s.id
	WHERE s.tenant_id = OLD.tenant_id AND s.class = 'review_campaigns' AND s.status = 'verified' AND i.item_id = CAST(OLD.campaign_id AS TEXT))
BEGIN SELECT RAISE(ABORT, 'review_auto_decisions is append-only'); END;
