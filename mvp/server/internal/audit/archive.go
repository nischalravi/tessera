package audit

import (
	"encoding/json"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Archived ranges of the chain (issue #298). The archival job (internal/archive)
// moves audit events past their retention into sealed segments and deletes them
// online, in one transaction that also appends an "audit.archived" event to the
// chain: the anchor. The chain stays verifiable end to end:
//
//   - the purged segments (archive_segments, class audit) cover seq 1..N with no
//     gap: each starts where the previous ended and its prev_hash is the
//     previous segment's last hash (genesis for the first);
//   - with an ArchiveSource, Verify opens each segment, recomputes every event's
//     hash, checks the links inside it, its first and last hash and its count
//     against the catalogue, and checks the signed checkpoints that fall in it;
//   - the online chain starts at N+1 with prev_hash equal to the last hash of
//     the newest segment;
//   - every purged segment has its "audit.archived" anchor in the chain (online
//     or inside a later segment) naming its range and last hash, so a segment
//     row cannot be added or dropped without the chain disagreeing.
//
// Without an ArchiveSource the archived range cannot be checked and Verify says
// so (kind archive_unchecked, a warning): it never reports ok for a range it
// did not read.

// ActionArchived is the action of the anchor event appended when a segment is purged.
const ActionArchived = "audit.archived"

// TargetArchiveSegment is the target type of the anchor event (its id is the segment id).
const TargetArchiveSegment = "archive_segment"

// ArchiveSource opens the sealed content of a purged audit segment: its events
// as the NDJSON lines of ExportRecord, in seq order. It must fail when the blob
// was altered (checksum or seal), not return partial content.
type ArchiveSource interface {
	OpenAuditSegment(t tenancy.ID, seg *store.ArchiveSegment) ([][]byte, error)
}

// ArchiveAnchor is the detail of the "audit.archived" event.
type ArchiveAnchor struct {
	SegmentID  string `json:"segment_id"`
	FromSeq    int64  `json:"from_seq"`
	ThroughSeq int64  `json:"through_seq"`
	Count      int64  `json:"count"`
	PrevHash   string `json:"prev_hash"`
	FirstHash  string `json:"first_hash"`
	LastHash   string `json:"last_hash"`
	SHA256     string `json:"sha256"`
	Location   string `json:"location"`
}

// Detail is the anchor as the audit detail object (JCS-safe: integers and strings).
func (a ArchiveAnchor) Detail() ojson.Object {
	return ojson.Object{{Key: "segment_id", Value: a.SegmentID}, {Key: "from_seq", Value: a.FromSeq},
		{Key: "through_seq", Value: a.ThroughSeq}, {Key: "count", Value: a.Count}, {Key: "prev_hash", Value: a.PrevHash},
		{Key: "first_hash", Value: a.FirstHash}, {Key: "last_hash", Value: a.LastHash}, {Key: "sha256", Value: a.SHA256},
		{Key: "location", Value: a.Location}}
}

// ArchivedEvent is one parsed line of an archived segment.
type ArchivedEvent struct {
	Seq      int64
	TenantID string
	Action   string
	PrevHash string
	Hash     string // the hash the line claims
	Computed string // the hash its fields give
	Detail   json.RawMessage
}

// HashOK reports whether the claimed hash is the hash of the fields.
func (e ArchivedEvent) HashOK() bool { return e.Hash == e.Computed }

// ParseArchivedLine reads one NDJSON line of an exported event and recomputes its hash.
func ParseArchivedLine(line []byte) (ArchivedEvent, error) {
	var rec struct {
		canon.Body
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return ArchivedEvent{}, fmt.Errorf("audit: archived record: %w", err)
	}
	_, computed, err := VerifyRecord(line)
	if err != nil {
		return ArchivedEvent{}, err
	}
	return ArchivedEvent{Seq: rec.Seq, TenantID: rec.TenantID, Action: rec.Action, PrevHash: rec.PrevHash, Hash: rec.Hash,
		Computed: computed, Detail: rec.Detail}, nil
}

type addFn func(code int, kind string, seq int64, format string, args ...any)

// archiveState is what Verify learns from the archived range.
type archiveState struct {
	base     int64  // the last archived seq (0: nothing archived)
	baseHash string // its hash (genesis when base is 0)
	opened   bool   // every purged segment was opened and checked
	hashAt   map[int64]string
	anchors  map[string]ArchiveAnchor
	purged   []*store.ArchiveSegment
}

// noteAnchor remembers an "audit.archived" event seen in the chain.
func (s *archiveState) noteAnchor(detail json.RawMessage) {
	var a ArchiveAnchor
	if json.Unmarshal(detail, &a) == nil && a.SegmentID != "" {
		s.anchors[a.SegmentID] = a
	}
}

// verifyArchive checks the purged audit segments: that they join up from
// genesis, and, with a source, their content. ckSeq is the set of checkpoint
// seqs, whose archived hashes are returned for the checkpoint check.
func verifyArchive(tx *store.TenantTx, o VerifyOptions, ckSeq map[int64]bool, add addFn, r *Report) (*archiveState, error) {
	st := &archiveState{baseHash: Genesis(tx.Tenant()), hashAt: map[int64]string{}, anchors: map[string]ArchiveAnchor{}}
	segs, err := tx.AuditArchiveSegments()
	if err != nil {
		return nil, err
	}
	for _, g := range segs {
		if g.Status == store.SegmentPurged {
			st.purged = append(st.purged, g)
		}
	}
	if len(st.purged) == 0 {
		return st, nil
	}
	next, prev := int64(1), Genesis(tx.Tenant())
	for _, g := range st.purged {
		switch {
		case g.SeqFrom > next:
			add(ExitSeqGap, "archive_gap", next, "events %d..%d are in no archive segment", next, g.SeqFrom-1)
		case g.SeqFrom < next:
			add(ExitSeqGap, "archive_overlap", g.SeqFrom, "archive segment %s starts at %d, inside the previous one", g.ID, g.SeqFrom)
		}
		if g.PrevHash != prev {
			add(ExitHashMismatch, "archive_link", g.SeqFrom, "archive segment %s does not continue the chain (prev_hash %.12s…, previous end %.12s…)",
				g.ID, g.PrevHash, prev)
		}
		next, prev = g.SeqTo+1, g.LastHash
	}
	st.base, st.baseHash = next-1, prev
	r.ArchivedThrough, r.ArchivedSegments = st.base, len(st.purged)
	if o.Archive == nil {
		add(0, "archive_unchecked", 0, "events 1..%d are in %d archive segments that were not opened: this range was not verified",
			st.base, len(st.purged))
		return st, nil
	}
	st.opened = true
	for _, g := range st.purged {
		lines, err := o.Archive.OpenAuditSegment(tx.Tenant(), g)
		if err != nil {
			st.opened = false
			add(ExitHashMismatch, "archive_corrupt", g.SeqFrom, "archive segment %s (events %d..%d) cannot be opened: %v", g.ID, g.SeqFrom, g.SeqTo, err)
			continue
		}
		if !verifySegmentLines(tx.Tenant(), g, lines, ckSeq, st, add) {
			st.opened = false
		}
		r.ArchivedEvents += int64(len(lines))
	}
	return st, nil
}

// verifySegmentLines checks one opened segment against its catalogue entry.
func verifySegmentLines(t tenancy.ID, g *store.ArchiveSegment, lines [][]byte, ckSeq map[int64]bool, st *archiveState, add addFn) bool {
	ok := true
	bad := func(code int, kind string, seq int64, format string, args ...any) {
		ok = false
		add(code, kind, seq, format, args...)
	}
	if int64(len(lines)) != g.Count || int64(len(lines)) != g.SeqTo-g.SeqFrom+1 {
		bad(ExitSeqGap, "archive_count", g.SeqFrom, "archive segment %s holds %d events, its range %d..%d has %d", g.ID, len(lines), g.SeqFrom, g.SeqTo, g.SeqTo-g.SeqFrom+1)
	}
	expect, prev := g.SeqFrom, g.PrevHash
	var first, last string
	var lastSeq int64
	for i, ln := range lines {
		ev, err := ParseArchivedLine(ln)
		if err != nil {
			bad(ExitHashMismatch, "archive_unreadable", expect, "archive segment %s line %d: %v", g.ID, i+1, err)
			expect++
			continue
		}
		if ev.TenantID != t.String() {
			bad(ExitHashMismatch, "wrong_tenant", ev.Seq, "archived event belongs to tenant %s", ev.TenantID)
		}
		if ev.Seq != expect {
			bad(ExitSeqGap, "archive_seq_gap", expect, "archive segment %s has seq %d where %d is expected", g.ID, ev.Seq, expect)
		}
		if !ev.HashOK() {
			bad(ExitHashMismatch, "archive_hash_mismatch", ev.Seq, "archived event stored hash %.12s… but its fields hash to %.12s… (altered)", ev.Hash, ev.Computed)
		}
		if ev.PrevHash != prev {
			bad(ExitHashMismatch, "archive_broken_link", ev.Seq, "archived event prev_hash %.12s… does not match the previous hash %.12s…", ev.PrevHash, prev)
		}
		if i == 0 {
			first = ev.Hash
		}
		if ckSeq[ev.Seq] {
			st.hashAt[ev.Seq] = ev.Hash
		}
		if ev.Action == ActionArchived {
			st.noteAnchor(ev.Detail)
		}
		prev, last, lastSeq, expect = ev.Hash, ev.Hash, ev.Seq, ev.Seq+1
	}
	if len(lines) > 0 && (first != g.FirstHash || last != g.LastHash || lastSeq != g.SeqTo) {
		bad(ExitHashMismatch, "archive_ends", g.SeqFrom, "archive segment %s ends do not match its catalogue entry (first %.12s…, last %.12s… at %d)", g.ID, first, last, lastSeq)
	}
	return ok
}

// VerifySegment checks the lines of one archived audit segment against its
// catalogue entry on their own: hashes recomputed, links inside the segment,
// its first and last hash, count and range. It is the check the archival job
// runs before it deletes anything, and the one behind Admin -> Archive ->
// Verify. Verify (the whole-chain check) adds how the segments join up.
func VerifySegment(t tenancy.ID, g *store.ArchiveSegment, lines [][]byte) []Problem {
	var ps []Problem
	add := func(code int, kind string, seq int64, format string, args ...any) {
		ps = append(ps, Problem{Code: code, Kind: kind, Seq: seq, Detail: fmt.Sprintf(format, args...)})
	}
	st := &archiveState{hashAt: map[int64]string{}, anchors: map[string]ArchiveAnchor{}}
	verifySegmentLines(t, g, lines, nil, st, add)
	return ps
}

// checkAnchors requires every purged segment to have its anchor in the chain.
func (s *archiveState) checkAnchors(add addFn) {
	for _, g := range s.purged {
		a, ok := s.anchors[g.ID]
		switch {
		case !ok:
			add(ExitSeqGap, "archive_anchor_missing", g.SeqTo, "archive segment %s (events %d..%d) has no %q event in the chain", g.ID, g.SeqFrom, g.SeqTo, ActionArchived)
		case a.FromSeq != g.SeqFrom || a.ThroughSeq != g.SeqTo || a.LastHash != g.LastHash || a.FirstHash != g.FirstHash || a.PrevHash != g.PrevHash || a.SHA256 != g.SHA256:
			add(ExitHashMismatch, "archive_anchor_mismatch", g.SeqTo, "the %q event of segment %s disagrees with the catalogue", ActionArchived, g.ID)
		}
	}
}
