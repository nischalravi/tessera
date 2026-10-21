package store

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"
)

// Archive segments and the records they replace (schema/0401, 0402, issue
// #298). The archival job lives in internal/archive; this file is only the
// SQL: the segment catalogue, and for each class the read of a record with its
// dependants and the delete of it. A delete only succeeds while the record's
// segment is 'verified' (the triggers of 0402 refuse it otherwise), so the
// order written, verified, purged is enforced by the database too.

// Archive segment statuses, in the only order they move.
const (
	SegmentWritten  = "written"
	SegmentVerified = "verified"
	SegmentPurged   = "purged"
	SegmentFailed   = "failed"
)

// Archive locations.
const (
	LocationLocal  = "local"
	LocationRemote = "remote"
)

// ArchiveSegment is the catalogue entry of one sealed segment.
type ArchiveSegment struct {
	ID    string
	Class string
	// Status is written, verified, purged or failed.
	Status string
	// SeqFrom and SeqTo are the chain range of an audit segment (0 for the other classes).
	SeqFrom, SeqTo int64
	// RangeFrom and RangeTo are the oldest and newest record time (RFC 3339), or the seqs of an audit segment.
	RangeFrom, RangeTo string
	Count              int64
	// PrevHash is the hash before SeqFrom (genesis for 1); FirstHash and LastHash are the hashes at SeqFrom and SeqTo.
	PrevHash, FirstHash, LastHash string
	Location, ObjectKey           string
	Size                          int64
	SHA256                        string // of the sealed blob
	CreatedAt                     time.Time
	VerifiedAt, PurgedAt          *time.Time
}

// ArchiveSegmentFilter narrows ArchiveSegments. Empty fields match everything.
type ArchiveSegmentFilter struct {
	Class, Status string
	Limit         int
}

const archiveSegmentCols = `g.id, g.class, g.status, g.seq_from, g.seq_to, g.range_from, g.range_to, g.item_count, g.prev_hash,
	g.first_hash, g.last_hash, g.location, g.object_key, g.size_bytes, g.sha256, g.created_at, g.verified_at, g.purged_at`

var (
	archiveSegmentInsert = tq("archive_segments.insert", `
		INSERT INTO archive_segments (id, tenant_id, class, status, seq_from, seq_to, range_from, range_to, item_count, prev_hash,
			first_hash, last_hash, location, object_key, size_bytes, sha256, created_at)
		VALUES (@id, @tenant, @class, 'written', @seq_from, @seq_to, @range_from, @range_to, @item_count, @prev_hash,
			@first_hash, @last_hash, @location, @object_key, @size_bytes, @sha256, @created_at)`)
	archiveItemInsert = tq("archive_segment_items.insert", `
		INSERT INTO archive_segment_items (tenant_id, segment_id, item_id) VALUES (@tenant, @segment_id, @item_id)`)
	archiveItemList = tq("archive_segment_items.list", `
		SELECT i.item_id FROM archive_segment_items i WHERE i.tenant_id = @tenant AND i.segment_id = @segment_id ORDER BY i.item_id`)
	archiveSegmentGet = tq("archive_segments.get", `
		SELECT `+archiveSegmentCols+` FROM archive_segments g WHERE g.tenant_id = @tenant AND g.id = @id`)
	archiveSegmentList = tq("archive_segments.list", `
		SELECT `+archiveSegmentCols+` FROM archive_segments g
		WHERE g.tenant_id = @tenant AND (@class = '' OR g.class = @class) AND (@status = '' OR g.status = @status)
		ORDER BY g.created_at DESC, g.id DESC LIMIT @limit`)
	archiveSegmentsAudit = tq("archive_segments.audit_chain", `
		SELECT `+archiveSegmentCols+` FROM archive_segments g
		WHERE g.tenant_id = @tenant AND g.class = 'audit' ORDER BY g.seq_from`)
	archiveSegmentsOpen = tq("archive_segments.open", `
		SELECT `+archiveSegmentCols+` FROM archive_segments g
		WHERE g.tenant_id = @tenant AND g.class = @class AND g.status <> 'purged' ORDER BY g.created_at, g.id`)
	archiveSegmentVerified = tq("archive_segments.mark_verified", `
		UPDATE archive_segments SET status = 'verified', verified_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'written'`)
	archiveSegmentFailed = tq("archive_segments.mark_failed", `
		UPDATE archive_segments SET status = 'failed'
		WHERE tenant_id = @tenant AND id = @id AND status IN ('written','verified')`)
	archiveSegmentPurged = tq("archive_segments.mark_purged", `
		UPDATE archive_segments SET status = 'purged', purged_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'verified'`)
	// Postgres has no DELETE grant on audit_events: its override calls the
	// SECURITY DEFINER function of 0402, which checks the tenant itself.
	auditArchivePurge = tq("audit_events.archive_purge", `
		DELETE FROM audit_events WHERE audit_events.tenant_id = @tenant
			AND seq >= (SELECT g.seq_from FROM archive_segments g WHERE g.tenant_id = @tenant AND g.id = @segment AND g.class = 'audit' AND g.status = 'verified')
			AND seq <= (SELECT g.seq_to FROM archive_segments g WHERE g.tenant_id = @tenant AND g.id = @segment AND g.class = 'audit' AND g.status = 'verified')`)
)

func scanArchiveSegment(s scanner) (*ArchiveSegment, error) {
	var g ArchiveSegment
	var created string
	var verified, purged sql.NullString
	if err := s.Scan(&g.ID, &g.Class, &g.Status, &g.SeqFrom, &g.SeqTo, &g.RangeFrom, &g.RangeTo, &g.Count, &g.PrevHash,
		&g.FirstHash, &g.LastHash, &g.Location, &g.ObjectKey, &g.Size, &g.SHA256, &created, &verified, &purged); err != nil {
		return nil, err
	}
	var err error
	if g.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if g.VerifiedAt, err = rtp(verified); err != nil {
		return nil, err
	}
	g.PurgedAt, err = rtp(purged)
	return &g, err
}

// InsertArchiveSegment records a segment that was just written to the archive store (status written).
func (tx *TenantTx) InsertArchiveSegment(g *ArchiveSegment) error {
	_, err := tx.exec(archiveSegmentInsert, sql.Named("id", g.ID), sql.Named("class", g.Class),
		sql.Named("seq_from", g.SeqFrom), sql.Named("seq_to", g.SeqTo), sql.Named("range_from", g.RangeFrom),
		sql.Named("range_to", g.RangeTo), sql.Named("item_count", g.Count), sql.Named("prev_hash", g.PrevHash),
		sql.Named("first_hash", g.FirstHash), sql.Named("last_hash", g.LastHash), sql.Named("location", g.Location),
		sql.Named("object_key", g.ObjectKey), sql.Named("size_bytes", g.Size), sql.Named("sha256", g.SHA256),
		sql.Named("created_at", RT(g.CreatedAt)))
	return err
}

// InsertArchiveSegmentItems records which requests or campaigns a segment holds (classes requests and
// review_campaigns), in the transaction that catalogues it. Only a verified segment's items unlock the
// delete guards of their append-only rows (schema/0403).
func (tx *TenantTx) InsertArchiveSegmentItems(segmentID string, ids []string) error {
	for _, id := range ids {
		if _, err := tx.exec(archiveItemInsert, sql.Named("segment_id", segmentID), sql.Named("item_id", id)); err != nil {
			return err
		}
	}
	return nil
}

// ArchiveSegmentItems lists the request or campaign ids of a segment.
func (tx *TenantTx) ArchiveSegmentItems(segmentID string) ([]string, error) {
	rows, err := tx.query(archiveItemList, sql.Named("segment_id", segmentID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ArchiveSegment returns one segment; ErrNotFound for another tenant's.
func (tx *TenantTx) ArchiveSegment(id string) (*ArchiveSegment, error) {
	return one(tx, scanArchiveSegment, archiveSegmentGet, sql.Named("id", id))
}

// ArchiveSegments lists segments, newest first.
func (tx *TenantTx) ArchiveSegments(f ArchiveSegmentFilter) ([]*ArchiveSegment, error) {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	return collect(tx, scanArchiveSegment, archiveSegmentList, sql.Named("class", f.Class), sql.Named("status", f.Status),
		sql.Named("limit", f.Limit))
}

// AuditArchiveSegments returns every audit segment, in chain order.
func (tx *TenantTx) AuditArchiveSegments() ([]*ArchiveSegment, error) {
	return collect(tx, scanArchiveSegment, archiveSegmentsAudit)
}

// OpenArchiveSegments returns the segments of a class that are not purged yet
// (written or verified): work an interrupted archival run left to finish.
func (tx *TenantTx) OpenArchiveSegments(class string) ([]*ArchiveSegment, error) {
	return collect(tx, scanArchiveSegment, archiveSegmentsOpen, sql.Named("class", class))
}

// MarkArchiveVerified moves a written segment to verified (ErrNotFound if it is not written).
func (tx *TenantTx) MarkArchiveVerified(id string, now time.Time) error {
	return tx.execOne(archiveSegmentVerified, sql.Named("id", id), sql.Named("now", RT(now)))
}

// MarkArchiveFailed gives up a segment whose blob could not be read back or did
// not match (ErrNotFound if it is already purged or failed). Its records stay online.
func (tx *TenantTx) MarkArchiveFailed(id string) error {
	return tx.execOne(archiveSegmentFailed, sql.Named("id", id))
}

// MarkArchivePurged moves a verified segment to purged (ErrNotFound if it is not verified).
func (tx *TenantTx) MarkArchivePurged(id string, now time.Time) error {
	return tx.execOne(archiveSegmentPurged, sql.Named("id", id), sql.Named("now", RT(now)))
}

// PurgeArchivedAudit deletes the audit events of one verified audit segment's
// seq range (nothing for any other segment id, status or class; on Postgres it
// is an error too). The schema refuses a delete of any event outside a verified segment.
func (tx *TenantTx) PurgeArchivedAudit(segmentID string) error {
	res, err := tx.exec(auditArchivePurge, sql.Named("segment", segmentID))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return errors.Join(ErrNotFound, err)
	}
	return nil
}

// ---------------------------------------------------------------- records

// ArchiveDoc is one record of a class with its dependants, as it is archived:
// the row and, per dependent table, its rows. Values are the column values;
// a BLOB column is "b64:" + base64.
type ArchiveDoc struct {
	ID       string                      `json:"id"`
	Record   map[string]any              `json:"record"`
	Children map[string][]map[string]any `json:"children,omitempty"`
}

var (
	jobRunArchiveCandidates = tq("archive.job_runs.candidates", `
		SELECT j.id FROM job_runs j WHERE j.tenant_id = @tenant AND j.status <> 'running' AND j.started_at < @before
		ORDER BY j.started_at, j.id LIMIT @limit`)
	jobRunArchiveRow    = tq("archive.job_runs.row", `SELECT j.* FROM job_runs j WHERE j.tenant_id = @tenant AND j.id = @id`)
	jobRunArchiveUnlink = tq("archive.job_runs.unlink", `
		UPDATE job_runs SET retry_of = NULL WHERE tenant_id = @tenant AND retry_of = @id`)
	jobRunArchiveDelete = tq("archive.job_runs.delete", `
		DELETE FROM job_runs WHERE tenant_id = @tenant AND id = @id AND status <> 'running'`)

	outboxArchiveCandidates = tq("archive.notifications.candidates", `
		SELECT n.id FROM notifications n WHERE n.tenant_id = @tenant AND n.created_at < @before
			AND n.delivery IN ('none','sent','skipped','dead','digested')
		ORDER BY n.created_at, n.id LIMIT @limit`)
	outboxArchiveRow   = tq("archive.notifications.row", `SELECT n.* FROM notifications n WHERE n.tenant_id = @tenant AND n.id = @id`)
	outboxArchiveEmail = tq("archive.notifications.email_messages", `
		SELECT m.* FROM email_messages m WHERE m.tenant_id = @tenant AND m.notification_id = @id ORDER BY m.id`)
	outboxArchiveDeleteEmail = tq("archive.notifications.delete_email_messages", `
		DELETE FROM email_messages WHERE tenant_id = @tenant AND notification_id = @id`)
	outboxArchiveDelete = tq("archive.notifications.delete", `DELETE FROM notifications WHERE tenant_id = @tenant AND id = @id`)

	requestArchiveCandidates = tq("archive.requests.candidates", `
		SELECT l.id FROM access_request_lines l WHERE l.tenant_id = @tenant
			AND l.status IN ('denied','cancelled','expired','removed')
			AND COALESCE(l.closed_at, l.decided_at, l.requested_at) < @before
		ORDER BY l.requested_at, l.id LIMIT @limit`)
	requestArchiveRow    = tq("archive.requests.row", `SELECT l.* FROM access_request_lines l WHERE l.tenant_id = @tenant AND l.id = @id`)
	requestArchiveEvents = tq("archive.requests.events", `
		SELECT e.* FROM access_request_events e WHERE e.tenant_id = @tenant AND e.line_id = @id ORDER BY e.id`)
	requestArchiveStages = tq("archive.requests.stages", `
		SELECT s.* FROM access_request_stages s WHERE s.tenant_id = @tenant AND s.line_id = @id ORDER BY s.idx`)
	requestArchiveDeleteEvents = tq("archive.requests.delete_events", `
		DELETE FROM access_request_events WHERE tenant_id = @tenant AND line_id = @id`)
	requestArchiveDeleteStages = tq("archive.requests.delete_stages", `
		DELETE FROM access_request_stages WHERE tenant_id = @tenant AND line_id = @id`)
	requestArchiveDelete = tq("archive.requests.delete", `
		DELETE FROM access_request_lines WHERE tenant_id = @tenant AND id = @id
			AND status IN ('denied','cancelled','expired','removed')`)

	// A campaign that group attestation or a business role exclusion still points at stays online.
	campaignArchiveCandidates = tq("archive.review_campaigns.candidates", `
		SELECT c.id FROM review_campaigns c
		WHERE c.tenant_id = @tenant AND c.status = 'completed' AND c.created_at < @before
			AND NOT EXISTS (SELECT 1 FROM grp_attest_campaigns g WHERE g.tenant_id = @tenant AND g.review_campaign_id = c.id)
			AND NOT EXISTS (SELECT 1 FROM grp_attest_items a JOIN review_items i ON i.id = a.review_item_id
				WHERE a.tenant_id = @tenant AND i.tenant_id = @tenant AND i.campaign_id = c.id)
			AND NOT EXISTS (SELECT 1 FROM business_role_exclusions e JOIN review_items i ON i.id = e.review_item_id
				WHERE e.tenant_id = @tenant AND i.tenant_id = @tenant AND i.campaign_id = c.id)
		ORDER BY c.id LIMIT @limit`)
	campaignArchiveRow = tq("archive.review_campaigns.row", `
		SELECT c.* FROM review_campaigns c WHERE c.tenant_id = @tenant AND c.id = @id`)
	campaignArchiveItems = tq("archive.review_campaigns.items", `
		SELECT i.* FROM review_items i WHERE i.tenant_id = @tenant AND i.campaign_id = @id ORDER BY i.id`)
	campaignArchiveItemRoles = tq("archive.review_campaigns.item_roles", `
		SELECT r.* FROM review_item_roles r JOIN review_items i ON i.id = r.item_id
		WHERE r.tenant_id = @tenant AND i.tenant_id = @tenant AND i.campaign_id = @id ORDER BY r.item_id`)
	campaignArchivePopulations = tq("archive.review_campaigns.populations", `
		SELECT p.* FROM review_populations p WHERE p.tenant_id = @tenant AND p.campaign_id = @id`)
	campaignArchivePopulationRows = tq("archive.review_campaigns.population_rows", `
		SELECT r.* FROM review_population_rows r WHERE r.tenant_id = @tenant AND r.campaign_id = @id ORDER BY r.ordinal`)
	campaignArchiveAutoDecisions = tq("archive.review_campaigns.auto_decisions", `
		SELECT a.* FROM review_auto_decisions a WHERE a.tenant_id = @tenant AND a.campaign_id = @id ORDER BY a.ordinal`)
	campaignArchiveLaunches = tq("archive.review_campaigns.launches", `
		SELECT l.* FROM review_launches l WHERE l.tenant_id = @tenant AND l.campaign_id = @id ORDER BY l.id`)
	campaignArchiveDeleteItemRoles = tq("archive.review_campaigns.delete_item_roles", `
		DELETE FROM review_item_roles WHERE review_item_roles.tenant_id = @tenant AND review_item_roles.item_id IN
			(SELECT i.id FROM review_items i WHERE i.tenant_id = @tenant AND i.campaign_id = @id)`)
	campaignArchiveDeleteItems = tq("archive.review_campaigns.delete_items", `
		DELETE FROM review_items WHERE tenant_id = @tenant AND campaign_id = @id`)
	campaignArchiveDeletePopulationRows = tq("archive.review_campaigns.delete_population_rows", `
		DELETE FROM review_population_rows WHERE tenant_id = @tenant AND campaign_id = @id`)
	campaignArchiveDeletePopulations = tq("archive.review_campaigns.delete_populations", `
		DELETE FROM review_populations WHERE tenant_id = @tenant AND campaign_id = @id`)
	campaignArchiveDeleteAutoDecisions = tq("archive.review_campaigns.delete_auto_decisions", `
		DELETE FROM review_auto_decisions WHERE tenant_id = @tenant AND campaign_id = @id`)
	campaignArchiveDeleteLaunches = tq("archive.review_campaigns.delete_launches", `
		DELETE FROM review_launches WHERE tenant_id = @tenant AND campaign_id = @id`)
	campaignArchiveDelete = tq("archive.review_campaigns.delete", `
		DELETE FROM review_campaigns WHERE tenant_id = @tenant AND id = @id AND status = 'completed'`)
)

// ErrArchiveClass is returned for a class with no record archive (audit has its own).
var ErrArchiveClass = errors.New("store: no record archive for this class")

// ArchiveCandidates returns up to limit ids of the class's records that are
// closed and older than before, oldest first. The audit class has its own
// path (a chain range, not records); ErrArchiveClass.
func (tx *TenantTx) ArchiveCandidates(class string, before time.Time, limit int) ([]string, error) {
	var s tstmt
	switch class {
	case ClassJobRuns:
		s = jobRunArchiveCandidates
	case ClassOutbox:
		s = outboxArchiveCandidates
	case ClassRequests:
		s = requestArchiveCandidates
	case ClassCampaigns:
		s = campaignArchiveCandidates
	default:
		return nil, ErrArchiveClass
	}
	rows, err := tx.query(s, sql.Named("before", T(before)), sql.Named("limit", limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id any
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, fmt.Sprint(docValue(id)))
	}
	return ids, rows.Err()
}

// campaignID parses a campaign id (an integer) for the statements.
func campaignID(id string) (int64, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("store: archive: %q is not a campaign id", id)
	}
	return n, nil
}

// ArchiveDocument reads one record of a class and its dependants; ErrNotFound if it is gone.
func (tx *TenantTx) ArchiveDocument(class, id string) (*ArchiveDoc, error) {
	var root tstmt
	var kids []struct {
		name string
		s    tstmt
	}
	var arg any = id
	switch class {
	case ClassJobRuns:
		root = jobRunArchiveRow
	case ClassOutbox:
		root = outboxArchiveRow
		kids = append(kids, struct {
			name string
			s    tstmt
		}{"email_messages", outboxArchiveEmail})
	case ClassRequests:
		root = requestArchiveRow
		kids = append(kids, struct {
			name string
			s    tstmt
		}{"access_request_events", requestArchiveEvents}, struct {
			name string
			s    tstmt
		}{"access_request_stages", requestArchiveStages})
	case ClassCampaigns:
		n, err := campaignID(id)
		if err != nil {
			return nil, err
		}
		arg = n
		root = campaignArchiveRow
		for _, k := range []struct {
			name string
			s    tstmt
		}{{"review_items", campaignArchiveItems}, {"review_item_roles", campaignArchiveItemRoles},
			{"review_populations", campaignArchivePopulations}, {"review_population_rows", campaignArchivePopulationRows},
			{"review_auto_decisions", campaignArchiveAutoDecisions}, {"review_launches", campaignArchiveLaunches}} {
			kids = append(kids, k)
		}
	default:
		return nil, ErrArchiveClass
	}
	rec, err := tx.queryDocs(root, sql.Named("id", arg))
	if err != nil {
		return nil, err
	}
	if len(rec) == 0 {
		return nil, ErrNotFound
	}
	d := &ArchiveDoc{ID: id, Record: rec[0]}
	for _, k := range kids {
		rows, err := tx.queryDocs(k.s, sql.Named("id", arg))
		if err != nil {
			return nil, err
		}
		if len(rows) > 0 {
			if d.Children == nil {
				d.Children = map[string][]map[string]any{}
			}
			d.Children[k.name] = rows
		}
	}
	return d, nil
}

// ArchiveDelete deletes one archived record and its dependants. The schema
// refuses the delete of an append-only row unless the class has a verified segment.
func (tx *TenantTx) ArchiveDelete(class, id string) error {
	run := func(steps ...struct {
		s   tstmt
		arg any
	}) error {
		for _, st := range steps {
			if _, err := tx.exec(st.s, sql.Named("id", st.arg)); err != nil {
				return err
			}
		}
		return nil
	}
	type step = struct {
		s   tstmt
		arg any
	}
	switch class {
	case ClassJobRuns:
		return run(step{jobRunArchiveUnlink, id}, step{jobRunArchiveDelete, id})
	case ClassOutbox:
		return run(step{outboxArchiveDeleteEmail, id}, step{outboxArchiveDelete, id})
	case ClassRequests:
		return run(step{requestArchiveDeleteEvents, id}, step{requestArchiveDeleteStages, id}, step{requestArchiveDelete, id})
	case ClassCampaigns:
		n, err := campaignID(id)
		if err != nil {
			return err
		}
		return run(step{campaignArchiveDeleteItemRoles, n}, step{campaignArchiveDeleteItems, n},
			step{campaignArchiveDeletePopulationRows, n}, step{campaignArchiveDeletePopulations, n},
			step{campaignArchiveDeleteAutoDecisions, n}, step{campaignArchiveDeleteLaunches, n}, step{campaignArchiveDelete, n})
	}
	return ErrArchiveClass
}

// queryDocs runs a SELECT of whole rows and returns each as column -> value.
func (tx *TenantTx) queryDocs(s tstmt, args ...sql.NamedArg) ([]map[string]any, error) {
	rows, err := tx.query(s, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			m[c] = docValue(vals[i])
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// docValue turns a scanned column into a JSON-safe value.
func docValue(v any) any {
	switch x := v.(type) {
	case []byte:
		if utf8.Valid(x) {
			return string(x)
		}
		return "b64:" + base64.StdEncoding.EncodeToString(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	}
	return v
}
