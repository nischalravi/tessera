-- Proof for the written -> verified transition of an archive segment (issue #401, reopened). The 0510
-- guards only required that a segment's recorded end hashes (audit) or at least one item (requests,
-- review_campaigns) existed, and the application role writes both the segment and its items, so a
-- forged segment could still be inserted 'written', given an item and UPDATEd to 'verified'. The
-- transition now recomputes, in the same statement, what the row claims:
--   * a per-record segment holds exactly item_count items;
--   * an audit segment's range is complete (one event per seq from seq_from to seq_to, item_count
--     of them), carries first_hash and last_hash at its ends, and every event in it links to the
--     hash of the one before (audit_events cannot be rewritten by the application role).
-- A segment that claims a range or items it does not hold is refused. SQLite has one process and one
-- role, so this raises the cost of a forgery but is not a privilege boundary; Postgres adds one
-- (schema/postgres/0520: only a SECURITY DEFINER function owned by the migration role may verify).
DROP TRIGGER IF EXISTS archive_segments_verify_evidence;
CREATE TRIGGER archive_segments_verify_evidence BEFORE UPDATE OF status ON archive_segments
WHEN OLD.status = 'written' AND NEW.status = 'verified' AND (
	(NEW.class IN ('requests','review_campaigns') AND
		(SELECT count(*) FROM archive_segment_items i WHERE i.tenant_id = NEW.tenant_id AND i.segment_id = NEW.id) <> NEW.item_count)
	OR (NEW.class = 'audit' AND (
		NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_from AND e.hash = NEW.first_hash)
		OR NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_to AND e.hash = NEW.last_hash)
		OR NEW.item_count <> NEW.seq_to - NEW.seq_from + 1
		OR (SELECT count(*) FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq >= NEW.seq_from AND e.seq <= NEW.seq_to) <> NEW.seq_to - NEW.seq_from + 1
		OR EXISTS (SELECT 1 FROM audit_events e JOIN audit_events p ON p.tenant_id = e.tenant_id AND p.seq = e.seq - 1
			WHERE e.tenant_id = NEW.tenant_id AND e.seq > NEW.seq_from AND e.seq <= NEW.seq_to AND e.prev_hash <> p.hash))))
BEGIN SELECT RAISE(ABORT, 'archive_segments: nothing backs this verification'); END;
