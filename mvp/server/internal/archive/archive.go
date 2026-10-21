// Package archive is Tessera's archival library (issue #298): the job that
// moves records past their retention (internal/retention) out of the online
// store into sealed archive segments, and the checks and exports around them.
//
// A segment is an NDJSON document, gzip-compressed and sealed under the KEK
// (internal/seal) with an AAD that binds the tenant, the class, the segment id
// and its range, so a segment cannot be replayed as another tenant's, another
// class's or another range. It lives in a BlobStore (a local directory or an
// HTTP object store through internal/safehttp) and has a catalogue row
// (archive_segments) holding its checksum and, for the audit class, the chain
// hashes at its ends.
//
// Crash-safe order, per segment (each step is its own transaction and each
// survives a crash at any point; the next run picks up where this one stopped):
//
//  1. write: seal the records, put the blob in the store, then catalogue it
//     (status written);
//  2. verify: read the blob back from the store, check its checksum, open it
//     and check its content against the catalogue and, for audit, the chain
//     (status verified); a blob that fails here is given up (status failed)
//     and its records stay online;
//  3. purge: check it again, then in one transaction delete the online records,
//     append the anchor event to the audit chain and mark the segment purged.
//     The schema refuses the delete unless the segment is verified (0402).
//
// The audit chain stays verifiable: see internal/audit/archive.go.
package archive

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/retention"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Actor is the system actor of the archival job.
const Actor = "archive.sweeper"

// Defaults of the per-run limits.
const (
	defaultAuditBatch  = 2000
	defaultDocBatch    = 200
	defaultSegments    = 5
	defaultMaxPlain    = 4 << 20
	maxInflatedBytes   = 64 << 20
	openTimeout        = 2 * time.Minute
	tableSegments      = "archive_segments"
	recordsPurgedEvent = "archive.purged"
)

// Service runs the archival job and the checks of archived segments.
type Service struct {
	DB     *store.DB
	Sealer *seal.Sealer
	Store  BlobStore
	Clock  func() time.Time
	Log    *slog.Logger
	// AuditBatch is the most events in one audit segment, DocBatch the most
	// records in one segment of another class, MaxPlain the plaintext size at
	// which a segment is closed, MaxSegments the most new segments per class and
	// run. Zero: the defaults (2000, 200, 4 MiB, 5).
	AuditBatch, DocBatch, MaxSegments int
	MaxPlain                          int
}

// Enabled reports whether archiving is configured: with no KEK or no store the
// job does nothing and nothing is ever deleted.
func (s *Service) Enabled() bool { return s != nil && s.DB != nil && s.Sealer != nil && s.Store != nil }

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func orDefault(n, d int) int {
	if n > 0 {
		return n
	}
	return d
}

// ContentError says a segment's blob is missing, altered or does not match its
// catalogue entry (as opposed to the store being unreachable).
type ContentError struct{ Msg string }

func (e *ContentError) Error() string { return e.Msg }

func content(format string, args ...any) error {
	return &ContentError{Msg: fmt.Sprintf(format, args...)}
}

// IsContent reports whether err is a ContentError.
func IsContent(err error) bool {
	var ce *ContentError
	return errors.As(err, &ce)
}

// ---------------------------------------------------------------- the blob

// rangeKey is the range part of a segment's AAD.
func rangeKey(g *store.ArchiveSegment) string {
	part := func(s string) string {
		if s == "" || strings.Contains(s, "|") {
			return "-"
		}
		return s
	}
	return fmt.Sprintf("%d-%d_%s_%s", g.SeqFrom, g.SeqTo, part(g.RangeFrom), part(g.RangeTo))
}

// segmentAAD binds a sealed segment to its tenant, class, id and range.
func segmentAAD(t tenancy.ID, g *store.ArchiveSegment) []byte {
	return seal.AAD(t, tableSegments, g.Class, g.ID, rangeKey(g))
}

func objectKey(t tenancy.ID, class, id string) string {
	return fmt.Sprintf("%s/%s/%s.seg", t.String(), class, id)
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func gz(plain []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxInflatedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflatedBytes {
		return nil, errors.New("segment inflates past the limit")
	}
	return out, nil
}

func splitLines(plain []byte) [][]byte {
	var out [][]byte
	for _, ln := range bytes.Split(plain, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) > 0 {
			out = append(out, ln)
		}
	}
	return out
}

// open reads a segment's blob back from the store and returns its lines. It
// checks the size and checksum of the blob against the catalogue, then opens
// the seal (which checks the AAD) and the compression, and the count. Store
// errors other than a missing object are returned as they are (retry later);
// everything else is a ContentError.
func (s *Service) open(ctx context.Context, t tenancy.ID, g *store.ArchiveSegment) ([][]byte, error) {
	data, err := s.Store.Get(ctx, g.ObjectKey)
	switch {
	case errors.Is(err, ErrMissing):
		return nil, content("the archive store has no object %s", g.ObjectKey)
	case err != nil:
		return nil, err
	}
	if int64(len(data)) != g.Size || sha256hex(data) != g.SHA256 {
		return nil, content("the stored segment does not match its checksum (altered or replaced)")
	}
	zipped, err := s.Sealer.Open(data, segmentAAD(t, g))
	if err != nil {
		return nil, content("the segment does not open under this tenant's key and its range (altered, or sealed for another range)")
	}
	plain, err := gunzip(zipped)
	if err != nil {
		return nil, content("the segment content is not readable: %v", err)
	}
	lines := splitLines(plain)
	if int64(len(lines)) != g.Count {
		return nil, content("the segment holds %d records, its catalogue entry says %d", len(lines), g.Count)
	}
	return lines, nil
}

// OpenAuditSegment implements audit.ArchiveSource for the chain verifier.
func (s *Service) OpenAuditSegment(t tenancy.ID, g *store.ArchiveSegment) ([][]byte, error) {
	if !s.Enabled() {
		return nil, errors.New("archiving is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	return s.open(ctx, t, g)
}

// check opens a segment and applies the checks of its class.
func (s *Service) check(ctx context.Context, t tenancy.ID, g *store.ArchiveSegment) ([][]byte, error) {
	lines, err := s.open(ctx, t, g)
	if err != nil {
		return nil, err
	}
	if g.Class == store.ClassAudit {
		if ps := audit.VerifySegment(t, g, lines); len(ps) > 0 {
			return nil, content("%s: %s", ps[0].Kind, ps[0].Detail)
		}
		return lines, nil
	}
	seen := map[string]bool{}
	for i, ln := range lines {
		var d store.ArchiveDoc
		if err := json.Unmarshal(ln, &d); err != nil || d.ID == "" || d.Record == nil {
			return nil, content("record %d of the segment is not an archived document", i+1)
		}
		if seen[d.ID] {
			return nil, content("record %s appears twice in the segment", d.ID)
		}
		seen[d.ID] = true
	}
	return lines, nil
}

// ---------------------------------------------------------------- the job

// ClassResult says what a run did for one class.
type ClassResult struct {
	Written  int   `json:"written"`
	Verified int   `json:"verified"`
	Purged   int   `json:"purged"`
	Failed   int   `json:"failed"`
	Records  int64 `json:"records"`
	Kept     int   `json:"kept,omitempty"` // records that changed since they were archived and stay online
}

// Result is what RunTenant did.
type Result struct {
	Classes map[string]*ClassResult `json:"classes"`
}

// Total returns how many segments the run moved forward.
func (r Result) Total() int {
	n := 0
	for _, c := range r.Classes {
		n += c.Written + c.Verified + c.Purged + c.Failed
	}
	return n
}

// RunTenant archives what is past retention in one tenant, class by class. A
// class that fails does not stop the others; the errors are joined.
func (s *Service) RunTenant(ctx context.Context, t tenancy.ID) (Result, error) {
	res := Result{Classes: map[string]*ClassResult{}}
	if !s.Enabled() {
		return res, nil
	}
	ctx = audit.WithSystemActor(ctx, Actor)
	var settings []retention.Setting
	if err := s.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		settings, err = retention.Effective(tx)
		return err
	}); err != nil {
		return res, err
	}
	now := s.now()
	var errs []error
	for _, st := range settings {
		cr := &ClassResult{}
		res.Classes[st.Name] = cr
		if err := s.runClass(ctx, t, st.Name, retention.Cutoff(now, st.Days), cr); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", st.Name, err))
		}
	}
	return res, errors.Join(errs...)
}

func (s *Service) runClass(ctx context.Context, t tenancy.ID, class string, cutoff time.Time, cr *ClassResult) error {
	// finish what an earlier run left half done, oldest first
	var open []*store.ArchiveSegment
	if err := s.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		open, err = tx.OpenArchiveSegments(class)
		return err
	}); err != nil {
		return err
	}
	for _, g := range open {
		if err := s.advance(ctx, t, g, cr); err != nil {
			return err
		}
	}
	for i := 0; i < orDefault(s.MaxSegments, defaultSegments); i++ {
		g, blob, ids, err := s.plan(ctx, t, class, cutoff)
		if err != nil {
			return err
		}
		if g == nil {
			return nil
		}
		// 1. write: the blob first, then its catalogue row
		if err := s.Store.Put(ctx, g.ObjectKey, blob); err != nil {
			return fmt.Errorf("write segment: %w", err)
		}
		if err := s.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
			if err := tx.InsertArchiveSegment(g); err != nil {
				return err
			}
			// the records it holds: only they are unlocked for delete once it is verified (schema/0403)
			if err := tx.InsertArchiveSegmentItems(g.ID, ids); err != nil {
				return err
			}
			_, err := audit.Record(ctx, tx, "archive.segment.written", segmentDetail(g), audit.At(s.now()),
				audit.Target(audit.TargetArchiveSegment, g.ID))
			return err
		}); err != nil {
			return err
		}
		cr.Written++
		if err := s.advance(ctx, t, g, cr); err != nil {
			return err
		}
	}
	return nil
}

func segmentDetail(g *store.ArchiveSegment) ojson.Object {
	d := ojson.Object{{Key: "segment_id", Value: g.ID}, {Key: "class", Value: g.Class}, {Key: "count", Value: g.Count},
		{Key: "range_from", Value: g.RangeFrom}, {Key: "range_to", Value: g.RangeTo}, {Key: "sha256", Value: g.SHA256},
		{Key: "size", Value: g.Size}, {Key: "location", Value: g.Location}}
	if g.Class == store.ClassAudit {
		d = append(d, ojson.KV{Key: "from_seq", Value: g.SeqFrom}, ojson.KV{Key: "through_seq", Value: g.SeqTo})
	}
	return d
}

// advance moves a segment as far as it can: written to verified to purged.
func (s *Service) advance(ctx context.Context, t tenancy.ID, g *store.ArchiveSegment, cr *ClassResult) error {
	if g.Status == store.SegmentWritten {
		// 2. verify: read it back from the store, as a restore would
		if _, err := s.check(ctx, t, g); err != nil {
			return s.giveUp(ctx, t, g, err, cr)
		}
		if err := s.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
			if err := tx.MarkArchiveVerified(g.ID, s.now()); err != nil {
				return err
			}
			_, err := audit.Record(ctx, tx, "archive.segment.verified", segmentDetail(g), audit.At(s.now()),
				audit.Target(audit.TargetArchiveSegment, g.ID))
			return err
		}); err != nil {
			return err
		}
		g.Status = store.SegmentVerified
		cr.Verified++
	}
	if g.Status == store.SegmentVerified {
		return s.purge(ctx, t, g, cr)
	}
	return nil
}

// giveUp records that a segment cannot be trusted. A content error marks it
// failed (its records stay online and are archived again in a new segment); a
// store error is returned and the segment is tried again next run.
func (s *Service) giveUp(ctx context.Context, t tenancy.ID, g *store.ArchiveSegment, cause error, cr *ClassResult) error {
	if !IsContent(cause) {
		return cause
	}
	s.log().Error("archive segment failed verification", "tenant", t.String(), "segment", g.ID, "class", g.Class, "error", cause)
	if err := s.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if err := tx.MarkArchiveFailed(g.ID); err != nil {
			return err
		}
		d := append(segmentDetail(g), ojson.KV{Key: "reason", Value: cause.Error()})
		_, err := audit.Record(ctx, tx, "archive.segment.failed", d, audit.At(s.now()),
			audit.Target(audit.TargetArchiveSegment, g.ID), audit.Outcome(store.OutcomeFailure))
		return err
	}); err != nil {
		return err
	}
	g.Status = store.SegmentFailed
	cr.Failed++
	return fmt.Errorf("segment %s failed verification and was given up: %w", g.ID, cause)
}

// purge deletes the online records of a verified segment (step 3).
func (s *Service) purge(ctx context.Context, t tenancy.ID, g *store.ArchiveSegment, cr *ClassResult) error {
	lines, err := s.check(ctx, t, g) // the blob must still be good right before the delete
	if err != nil {
		return s.giveUp(ctx, t, g, err, cr)
	}
	var kept int
	err = s.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		kept = 0
		now := s.now()
		if g.Class == store.ClassAudit {
			// the anchor first: it is a new event after the range, so the range's
			// last event is never the head the chain guards need
			a := audit.ArchiveAnchor{SegmentID: g.ID, FromSeq: g.SeqFrom, ThroughSeq: g.SeqTo, Count: g.Count, PrevHash: g.PrevHash,
				FirstHash: g.FirstHash, LastHash: g.LastHash, SHA256: g.SHA256, Location: g.Location}
			if _, err := audit.Record(ctx, tx, audit.ActionArchived, a.Detail(), audit.At(now),
				audit.Target(audit.TargetArchiveSegment, g.ID)); err != nil {
				return err
			}
			if err := tx.PurgeArchivedAudit(g.ID); err != nil {
				return err
			}
			if n, _, _, err := tx.AuditEventStats(1, g.SeqTo); err != nil {
				return err
			} else if n != 0 {
				return fmt.Errorf("archive: %d audit events up to %d are still online after the purge", n, g.SeqTo)
			}
			return tx.MarkArchivePurged(g.ID, now)
		}
		for _, ln := range lines {
			var d store.ArchiveDoc
			if err := json.Unmarshal(ln, &d); err != nil {
				return err
			}
			cur, err := tx.ArchiveDocument(g.Class, d.ID)
			if errors.Is(err, store.ErrNotFound) {
				continue // already gone
			}
			if err != nil {
				return err
			}
			if b, err := json.Marshal(cur); err != nil || !bytes.Equal(b, ln) {
				kept++ // changed since it was archived: it stays online, and is archived again when it is next due
				continue
			}
			if err := tx.ArchiveDelete(g.Class, d.ID); err != nil {
				return err
			}
		}
		if err := tx.MarkArchivePurged(g.ID, now); err != nil {
			return err
		}
		d := append(segmentDetail(g), ojson.KV{Key: "kept_online", Value: kept})
		_, err := audit.Record(ctx, tx, recordsPurgedEvent, d, audit.At(now), audit.Target(audit.TargetArchiveSegment, g.ID))
		return err
	})
	if err != nil {
		return err
	}
	g.Status = store.SegmentPurged
	cr.Purged++
	cr.Records += g.Count - int64(kept)
	cr.Kept += kept
	return nil
}

// ---------------------------------------------------------------- planning

// plan reads the next batch of a class that is past the cutoff and returns the
// sealed segment (nil when nothing is due). It writes nothing.
func (s *Service) plan(ctx context.Context, t tenancy.ID, class string, cutoff time.Time) (*store.ArchiveSegment, []byte, []string, error) {
	var lines [][]byte
	var ids []string
	g := &store.ArchiveSegment{ID: uuid.NewString(), Class: class, Status: store.SegmentWritten, Location: s.Store.Location(),
		CreatedAt: s.now()}
	err := s.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		if class == store.ClassAudit {
			lines, err = s.planAudit(tx, g, cutoff)
		} else {
			lines, ids, err = s.planDocs(tx, g, cutoff)
		}
		return err
	})
	if err != nil || len(lines) == 0 {
		return nil, nil, nil, err
	}
	g.Count = int64(len(lines))
	g.ObjectKey = objectKey(t, class, g.ID)
	plain := append(bytes.Join(lines, []byte("\n")), '\n')
	zipped, err := gz(plain)
	if err != nil {
		return nil, nil, nil, err
	}
	blob, err := s.Sealer.Seal(zipped, segmentAAD(t, g))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("seal segment: %w", err)
	}
	g.Size, g.SHA256 = int64(len(blob)), sha256hex(blob)
	return g, blob, ids, nil
}

// planAudit takes the oldest events past the cutoff that no segment covers.
// It never takes the chain head, and it refuses to start a segment whose first
// event does not continue the chain (a gap or an edited row below the range is
// for the verifier to report, not for the archive to bury).
func (s *Service) planAudit(tx *store.TenantTx, g *store.ArchiveSegment, cutoff time.Time) ([][]byte, error) {
	segs, err := tx.AuditArchiveSegments()
	if err != nil {
		return nil, err
	}
	next, prev := int64(1), audit.Genesis(tx.Tenant())
	for _, o := range segs {
		if o.Status != store.SegmentFailed && o.SeqTo >= next {
			next, prev = o.SeqTo+1, o.LastHash
		}
	}
	head, err := tx.AuditHead()
	if err != nil {
		return nil, err
	}
	limit := orDefault(s.AuditBatch, defaultAuditBatch)
	evs, err := tx.AuditEventsRange(next, 0, limit)
	if err != nil {
		return nil, err
	}
	var lines [][]byte
	size := 0
	for i, e := range evs {
		if e.Seq != next+int64(i) {
			return nil, fmt.Errorf("archive: audit event %d is missing below the archive range (found %d): run the chain verification", next+int64(i), e.Seq)
		}
		if e.Seq >= head.LastSeq || !e.OccurredAt.Before(cutoff) || (len(lines) > 0 && size >= orDefault(s.MaxPlain, defaultMaxPlain)) {
			break
		}
		rec, err := audit.ExportRecord(e)
		if err != nil {
			return nil, err
		}
		line, err := ojson.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if len(lines) == 0 {
			if e.PrevHash != prev {
				return nil, fmt.Errorf("archive: audit event %d does not continue the chain (prev_hash %.12s…, expected %.12s…): run the chain verification", e.Seq, e.PrevHash, prev)
			}
			g.SeqFrom, g.PrevHash, g.FirstHash, g.RangeFrom = e.Seq, e.PrevHash, e.Hash, e.OccurredAt.UTC().Format(time.RFC3339)
		}
		g.SeqTo, g.LastHash, g.RangeTo = e.Seq, e.Hash, e.OccurredAt.UTC().Format(time.RFC3339)
		lines = append(lines, line)
		size += len(line) + 1
	}
	return lines, nil
}

// timeKey is the column that dates a record of each class (the range of a segment).
var timeKey = map[string]string{store.ClassJobRuns: "started_at", store.ClassOutbox: "created_at",
	store.ClassRequests: "requested_at", store.ClassCampaigns: "created_at"}

// planDocs takes the oldest closed records past the cutoff with their dependants.
func (s *Service) planDocs(tx *store.TenantTx, g *store.ArchiveSegment, cutoff time.Time) ([][]byte, []string, error) {
	cands, err := tx.ArchiveCandidates(g.Class, cutoff, orDefault(s.DocBatch, defaultDocBatch))
	if err != nil {
		return nil, nil, err
	}
	var lines [][]byte
	var ids []string
	size := 0
	for _, id := range cands {
		d, err := tx.ArchiveDocument(g.Class, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		b, err := json.Marshal(d)
		if err != nil {
			return nil, nil, err
		}
		if len(lines) > 0 && size+len(b) > orDefault(s.MaxPlain, defaultMaxPlain) {
			break
		}
		at, _ := d.Record[timeKey[g.Class]].(string)
		if len(lines) == 0 {
			g.RangeFrom = at
		}
		g.RangeTo = at
		lines = append(lines, b)
		ids = append(ids, d.ID)
		size += len(b) + 1
	}
	if g.RangeFrom == "" {
		g.RangeFrom, g.RangeTo = "-", "-"
	}
	return lines, ids, nil
}

// ---------------------------------------------------------------- admin checks

// SegmentCheck is the outcome of verifying one segment on demand.
type SegmentCheck struct {
	SegmentID string `json:"segment_id"`
	OK        bool   `json:"ok"`
	// Checks says what was checked, in order.
	Checks    []string `json:"checks"`
	Problem   string   `json:"problem,omitempty"`
	Records   int64    `json:"records"`
	CheckedAt string   `json:"checked_at"`
}

// Verify reads a segment back from the store and checks it: checksum, seal and
// range binding, count, and its content (the hash chain of an audit segment,
// the documents of another class). A content problem is the answer, not an
// error; an unreachable store is an error.
func (s *Service) Verify(ctx context.Context, t tenancy.ID, g *store.ArchiveSegment) (SegmentCheck, error) {
	out := SegmentCheck{SegmentID: g.ID, CheckedAt: s.now().Format(time.RFC3339)}
	if !s.Enabled() {
		return out, errors.New("archiving is not configured")
	}
	lines, err := s.check(ctx, t, g)
	if err != nil {
		if IsContent(err) {
			out.Problem = err.Error()
			return out, nil
		}
		return out, err
	}
	out.OK, out.Records = true, int64(len(lines))
	out.Checks = []string{"stored object matches its checksum", "opens under this tenant's key and its range", "record count matches"}
	if g.Class == store.ClassAudit {
		out.Checks = append(out.Checks, "every event hash recomputed, links and both ends match the chain")
	} else {
		out.Checks = append(out.Checks, "every record is a complete archived document")
	}
	return out, nil
}

// Export streams the segment's records as NDJSON, after checking them: the
// read-only restore. For an audit segment each line is the portable event of
// audit.ExportRecord (verifiable offline); for another class it is the
// archived document. Nothing is written back to the online store.
func (s *Service) Export(ctx context.Context, t tenancy.ID, g *store.ArchiveSegment, w io.Writer) (int, error) {
	if !s.Enabled() {
		return 0, errors.New("archiving is not configured")
	}
	lines, err := s.check(ctx, t, g)
	if err != nil {
		return 0, err
	}
	for _, ln := range lines {
		if _, err := w.Write(append(append([]byte{}, ln...), '\n')); err != nil {
			return 0, err
		}
	}
	return len(lines), nil
}
