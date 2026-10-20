package pit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The daily digest (design §10.2, K9). At 00:05 UTC a job hashes the previous
// day's grp_events rows into a Merkle tree and appends groups.pit.digest
// {day, first_seq, last_seq, event_count, root} to the audit ledger, whose
// checkpoints are anchored outside the database. Changing, deleting or adding
// an event of a digested day afterwards changes the root, which Verify finds.
//
// Leaves are SHA-256(0x00 || JCS(event row)), inner nodes SHA-256(0x01 ||
// left || right), and the tree is split as in RFC 6962 section 2.1, so any
// implementation of that tree reproduces the root from the exported events.

// Audit actions of this package.
const (
	ActionDigest    = "groups.pit.digest"
	ActionRebuild   = "groups.pit.rebuilt"
	ActionMismatch  = "groups.pit.mismatch"
	ActionRetention = "groups.retention.pruned"
)

// Errors of digests.
var (
	// ErrNoEvents is returned for a day without events (no digest is written).
	ErrNoEvents = errors.New("pit: no events on that day")
	// ErrDayOpen is returned for a day that has not ended yet.
	ErrDayOpen = errors.New("pit: the day has not ended")
	// ErrBadDay is returned for a day that is not YYYY-MM-DD.
	ErrBadDay = errors.New("pit: day must be YYYY-MM-DD")
)

const (
	dayLayout = "2006-01-02"
	pageSize  = 1000
)

// ParseDay reads a YYYY-MM-DD day and returns its UTC start and end.
func ParseDay(day string) (from, to time.Time, err error) {
	t, perr := time.Parse(dayLayout, day)
	if perr != nil || t.Format(dayLayout) != day {
		return from, to, ErrBadDay
	}
	return t, t.AddDate(0, 0, 1), nil
}

// Day is the YYYY-MM-DD of an instant in UTC.
func Day(t time.Time) string { return t.UTC().Format(dayLayout) }

func leafHash(canonical []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(canonical)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot is the root of the RFC 6962 tree over leaf hashes (at least one).
func MerkleRoot(leaves [][32]byte) ([32]byte, error) {
	switch n := len(leaves); n {
	case 0:
		return [32]byte{}, ErrNoEvents
	case 1:
		return leaves[0], nil
	default:
		k := 1
		for k*2 < n {
			k *= 2
		}
		l, _ := MerkleRoot(leaves[:k])
		r, _ := MerkleRoot(leaves[k:])
		return nodeHash(l, r), nil
	}
}

// DayRoot is the Merkle root of one day's events with the range it covers.
type DayRoot struct {
	Day      string
	FirstSeq int64
	LastSeq  int64
	Count    int64
	Root     string
}

// ComputeDay hashes the events that occurred on a UTC day. It returns
// ErrNoEvents if there are none.
func ComputeDay(tx *store.TenantTx, day string) (*DayRoot, error) {
	from, to, err := ParseDay(day)
	if err != nil {
		return nil, err
	}
	var leaves [][32]byte
	r := &DayRoot{Day: day}
	for after := int64(0); ; {
		page, err := tx.GrpEventsOfDay(from, to, after, pageSize)
		if err != nil {
			return nil, err
		}
		for _, e := range page {
			c, err := events.Canonical(e)
			if err != nil {
				return nil, err
			}
			leaves = append(leaves, leafHash(c))
			if r.Count == 0 {
				r.FirstSeq = e.Seq
			}
			r.LastSeq = e.Seq
			r.Count++
		}
		if len(page) < pageSize {
			break
		}
		after = page[len(page)-1].Seq
	}
	root, err := MerkleRoot(leaves)
	if err != nil {
		return nil, err
	}
	r.Root = hex.EncodeToString(root[:])
	return r, nil
}

// WriteDigest computes the digest of a finished day, appends it to the audit
// ledger and stores it, all in tx. A day that already has a digest returns the
// stored one (created is false), so the job is safe to repeat.
func WriteDigest(tx *store.TenantTx, day string, now time.Time) (d *store.PitDigest, created bool, err error) {
	_, end, err := ParseDay(day)
	if err != nil {
		return nil, false, err
	}
	if now.Before(end) {
		return nil, false, ErrDayOpen
	}
	if d, err := tx.GrpDigest(day); err == nil {
		return d, false, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}
	r, err := ComputeDay(tx, day)
	if err != nil {
		return nil, false, err
	}
	ev, err := tx.RecordAudit(store.AuditRecord{At: now, Action: ActionDigest, LegacyActor: "groups.pit",
		TargetType: "group_events", TargetID: day, Detail: ojson.Object{{Key: "day", Value: day},
			{Key: "first_seq", Value: r.FirstSeq}, {Key: "last_seq", Value: r.LastSeq}, {Key: "event_count", Value: r.Count},
			{Key: "root", Value: r.Root}}})
	if err != nil {
		return nil, false, err
	}
	d = &store.PitDigest{Day: day, FirstSeq: r.FirstSeq, LastSeq: r.LastSeq, EventCount: r.Count, MerkleRoot: r.Root,
		AuditSeq: ev.Seq, CreatedAt: now}
	return d, true, tx.InsertGrpDigest(*d)
}

// Digest verdicts.
const (
	VerdictOK             = "ok"
	VerdictMismatch       = "mismatch"        // the day's events no longer hash to the digest
	VerdictNoDigest       = "no_digest"       // the day has no digest (yet)
	VerdictPruned         = "pruned"          // retention removed events of the day; the digest stays as evidence
	VerdictLedgerMismatch = "ledger_mismatch" // the digest row disagrees with the audit ledger's copy
)

// Verdict is the outcome of verifying one day.
type Verdict struct {
	Day    string `json:"day"`
	Status string `json:"status"`
	// Detail says what differed, for a mismatch.
	Detail   string `json:"detail,omitempty"`
	Expected string `json:"expected_root,omitempty"`
	Got      string `json:"computed_root,omitempty"`
}

// OK says the day verified.
func (v Verdict) OK() bool { return v.Status == VerdictOK }

// VerifyDay recomputes a day's Merkle root and compares it with the stored
// digest and with the copy in the audit ledger.
func VerifyDay(tx *store.TenantTx, day string) (Verdict, error) {
	v := Verdict{Day: day}
	if _, _, err := ParseDay(day); err != nil {
		return v, err
	}
	d, err := tx.GrpDigest(day)
	if errors.Is(err, store.ErrNotFound) {
		v.Status = VerdictNoDigest
		return v, nil
	}
	if err != nil {
		return v, err
	}
	v.Expected = d.MerkleRoot
	// the ledger is the anchor: the digest row must say what the ledger says
	ev, err := tx.AuditEventBySeq(d.AuditSeq)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return v, err
	}
	var led struct {
		Day   string `json:"day"`
		Root  string `json:"root"`
		First int64  `json:"first_seq"`
		Last  int64  `json:"last_seq"`
		Count int64  `json:"event_count"`
	}
	if err != nil || ev.Action != ActionDigest || json.Unmarshal(ev.Detail, &led) != nil {
		v.Status, v.Detail = VerdictLedgerMismatch, "the audit ledger has no matching groups.pit.digest event"
		return v, nil
	}
	if led.Day != d.Day || led.Root != d.MerkleRoot || led.First != d.FirstSeq || led.Last != d.LastSeq || led.Count != d.EventCount {
		v.Status, v.Detail, v.Expected, v.Got = VerdictLedgerMismatch, "the stored digest differs from the ledger's copy", led.Root, d.MerkleRoot
		return v, nil
	}
	head, err := tx.GrpEventHead()
	if err != nil {
		return v, err
	}
	if head.PrunedSeq >= d.FirstSeq {
		v.Status = VerdictPruned
		return v, nil
	}
	r, err := ComputeDay(tx, day)
	switch {
	case errors.Is(err, ErrNoEvents):
		v.Status, v.Detail = VerdictMismatch, fmt.Sprintf("the %d events of the day are gone", d.EventCount)
		return v, nil
	case err != nil:
		return v, err
	}
	v.Got = r.Root
	if r.Root != d.MerkleRoot || r.FirstSeq != d.FirstSeq || r.LastSeq != d.LastSeq || r.Count != d.EventCount {
		v.Status = VerdictMismatch
		v.Detail = fmt.Sprintf("digest has %d events (seq %d..%d), the day now has %d (seq %d..%d)",
			d.EventCount, d.FirstSeq, d.LastSeq, r.Count, r.FirstSeq, r.LastSeq)
		return v, nil
	}
	v.Status = VerdictOK
	return v, nil
}

// VerifyAll verifies the newest limit digests, newest first.
func VerifyAll(tx *store.TenantTx, limit int) ([]Verdict, error) {
	ds, err := tx.GrpDigests(limit)
	if err != nil {
		return nil, err
	}
	out := make([]Verdict, 0, len(ds))
	for _, d := range ds {
		v, err := VerifyDay(tx, d.Day)
		if err != nil {
			return out, err
		}
		out = append(out, v)
	}
	return out, nil
}
