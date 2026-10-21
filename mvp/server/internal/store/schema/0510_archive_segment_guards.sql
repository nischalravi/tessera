-- Forge guards of the archive catalogue (issue #401). The delete guards of 0402 and 0403 trust a
-- segment row's status = 'verified', and the application role can write that row. Triggers cannot
-- prove a blob exists, so they close the shortcuts instead:
--   * a segment is INSERTed 'written' only (no verified_at, no purged_at): "verified" can only be
--     reached by the one forward UPDATE, never by an insert;
--   * archive_segment_items rows are added only while the parent is 'written', so a verified
--     segment never gains records it did not hold when it was verified (0403 already refuses
--     UPDATE and DELETE of items);
--   * a segment of a per-record class (requests, review_campaigns) cannot become verified with no
--     items, and an audit segment only when the audit events at both ends of its range exist and
--     carry first_hash and last_hash (the hash chain is the independent record of the range).
-- Purging an audit range names the segment: the delete statement takes a segment id and removes only
-- that segment's seq_from..seq_to (store.PurgeArchivedAudit; on Postgres tessera_archive_purge_audit).
CREATE TRIGGER IF NOT EXISTS archive_segments_insert_written BEFORE INSERT ON archive_segments
WHEN NEW.status <> 'written' OR NEW.verified_at IS NOT NULL OR NEW.purged_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'archive_segments are inserted as written'); END;

CREATE TRIGGER IF NOT EXISTS archive_segment_items_parent_written BEFORE INSERT ON archive_segment_items
WHEN NOT EXISTS (SELECT 1 FROM archive_segments p WHERE p.id = NEW.segment_id AND p.tenant_id = NEW.tenant_id AND p.status = 'written')
BEGIN SELECT RAISE(ABORT, 'archive_segment_items: the segment is not open for items'); END;

CREATE TRIGGER IF NOT EXISTS archive_segments_verify_evidence BEFORE UPDATE OF status ON archive_segments
WHEN OLD.status = 'written' AND NEW.status = 'verified' AND (
	(NEW.class IN ('requests','review_campaigns') AND NOT EXISTS (SELECT 1 FROM archive_segment_items i WHERE i.tenant_id = NEW.tenant_id AND i.segment_id = NEW.id))
	OR (NEW.class = 'audit' AND (
		NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_from AND e.hash = NEW.first_hash)
		OR NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq_to AND e.hash = NEW.last_hash))))
BEGIN SELECT RAISE(ABORT, 'archive_segments: nothing backs this verification'); END;
