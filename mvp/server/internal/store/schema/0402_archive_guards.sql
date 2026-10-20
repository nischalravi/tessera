-- Delete guards of archived records (issue #298). The ledger and the request
-- event log are append-only (0004, 0205); the one exception is a record whose
-- archive segment has been written, read back and verified (status
-- 'verified' in archive_segments, 0401). The archival job deletes inside the
-- transaction that moves the segment to 'purged', so a delete outside that
-- window still aborts.
--
-- The triggers are dropped and created again on every start (SQLite schema
-- files are applied in order each time), after 0004 and 0205 created theirs.

DROP TRIGGER IF EXISTS audit_events_no_delete;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
WHEN NOT EXISTS (SELECT 1 FROM archive_segments s
	WHERE s.tenant_id = OLD.tenant_id AND s.class = 'audit' AND s.status = 'verified'
		AND OLD.seq >= s.seq_from AND OLD.seq <= s.seq_to)
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

DROP TRIGGER IF EXISTS tg_access_request_events_no_delete;
CREATE TRIGGER tg_access_request_events_no_delete BEFORE DELETE ON access_request_events
WHEN NOT EXISTS (SELECT 1 FROM archive_segments s
	WHERE s.tenant_id = OLD.tenant_id AND s.class = 'requests' AND s.status = 'verified')
BEGIN SELECT RAISE(ABORT, 'access_request_events is append-only'); END;

-- The frozen review population and its auto-decisions (0350) go with their campaign
-- once the campaign's segment is verified.
DROP TRIGGER IF EXISTS review_populations_no_delete;
CREATE TRIGGER review_populations_no_delete BEFORE DELETE ON review_populations
WHEN NOT EXISTS (SELECT 1 FROM archive_segments s
	WHERE s.tenant_id = OLD.tenant_id AND s.class = 'review_campaigns' AND s.status = 'verified')
BEGIN SELECT RAISE(ABORT, 'review_populations is immutable'); END;

DROP TRIGGER IF EXISTS review_population_rows_no_delete;
CREATE TRIGGER review_population_rows_no_delete BEFORE DELETE ON review_population_rows
WHEN NOT EXISTS (SELECT 1 FROM archive_segments s
	WHERE s.tenant_id = OLD.tenant_id AND s.class = 'review_campaigns' AND s.status = 'verified')
BEGIN SELECT RAISE(ABORT, 'review_population_rows is immutable'); END;

DROP TRIGGER IF EXISTS review_auto_decisions_no_delete;
CREATE TRIGGER review_auto_decisions_no_delete BEFORE DELETE ON review_auto_decisions
WHEN NOT EXISTS (SELECT 1 FROM archive_segments s
	WHERE s.tenant_id = OLD.tenant_id AND s.class = 'review_campaigns' AND s.status = 'verified')
BEGIN SELECT RAISE(ABORT, 'review_auto_decisions is append-only'); END;
