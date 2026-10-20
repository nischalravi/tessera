-- Delete guard of archived audit events (issue #298). The ledger is append-only (0004);
-- the one exception is an event inside the seq range of an audit segment that has been
-- written, read back and verified (status 'verified' in archive_segments, 0401). The archival job deletes inside the
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

-- The request event log and the frozen review populations of campaigns are guarded per
-- record, by archive_segment_items: see 0403_archive_segment_items.sql.
