package audit

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Exit codes of `tessera audit verify` (design §13.7).
const (
	ExitOK                = 0
	ExitHashMismatch      = 2 // an event's hash does not match its fields, or a link is broken (edited row)
	ExitSeqGap            = 3 // a seq is missing or duplicated (deleted row)
	ExitCheckpointInvalid = 4 // a checkpoint signature or payload is invalid (forged checkpoint)
	ExitAnchorMissing     = 5 // a checkpoint is missing from the anchor source or differs there
	ExitStaleAnchoring    = 6 // events older than StaleAfter are not covered by an anchored checkpoint (warning unless strict)
)

// StaleAfter is how old an event may be without an anchored checkpoint
// covering it before verification warns (design: ≤ 10 min).
const StaleAfter = 10 * time.Minute

// Problem is one verification finding.
type Problem struct {
	Code   int    `json:"code"`
	Kind   string `json:"kind"`
	Seq    int64  `json:"seq,omitempty"`
	Detail string `json:"detail"`
}

// Report is the result of verifying one tenant's chain.
type Report struct {
	TenantID    string    `json:"tenant_id"`
	Tenant      string    `json:"tenant"`
	Events      int64     `json:"events"`
	FirstSeq    int64     `json:"first_seq"`
	LastSeq     int64     `json:"last_seq"`
	HeadSeq     int64     `json:"head_seq"`
	Checkpoints int       `json:"checkpoints"`
	Anchored    int       `json:"anchored"`
	Result      string    `json:"result"` // ok | warning | failed
	ExitCode    int       `json:"exit_code"`
	Problems    []Problem `json:"problems"`
}

// VerifyOptions scope and configure a verification.
type VerifyOptions struct {
	FromSeq, ToSeq int64 // 0: from the first / to the head
	// Keys are the platform public keys by kid (PlatformPublicKeys). With
	// none, every checkpoint fails verification.
	Keys map[string]ed25519.PublicKey
	// Anchors, when set, must contain every checkpoint's exact JWS.
	Anchors *AnchorSet
	Now     time.Time
	// Strict makes stale anchoring (exit 6) an error rather than a warning.
	Strict bool
}

// maxProblems caps the problems listed in one report.
const maxProblems = 100

const verifyPage = 1000

// Verify checks tx's tenant chain (design §13.7): events have consecutive
// seqs, each prev_hash links to the previous event (genesis for seq 1) and
// each hash matches its fields; the head matches the last event; every
// checkpoint is signed by a platform key, names this tenant, and certifies
// the hash of the event at its seq; and, with Anchors, every checkpoint was
// anchored with the same JWS. slug is for the report only.
func Verify(tx *store.TenantTx, slug string, o VerifyOptions) (Report, error) {
	r := Report{TenantID: tx.Tenant().String(), Tenant: slug, Problems: []Problem{}}
	add := func(code int, kind string, seq int64, format string, args ...any) {
		if len(r.Problems) < maxProblems {
			r.Problems = append(r.Problems, Problem{Code: code, Kind: kind, Seq: seq, Detail: fmt.Sprintf(format, args...)})
		}
		if code == ExitStaleAnchoring && !o.Strict {
			return
		}
		if r.ExitCode == 0 || code < r.ExitCode {
			r.ExitCode = code
		}
	}
	from := max(o.FromSeq, 1)
	to := o.ToSeq
	head, err := tx.AuditHead()
	if err != nil {
		return r, err
	}
	r.HeadSeq = head.LastSeq

	checkpoints, err := tx.AuditCheckpoints(from, to)
	if err != nil {
		return r, err
	}
	ckSeq := map[int64]bool{}
	timeAt := map[int64]bool{from: true} // the first event after each checkpoint (stale-anchoring check)
	for _, c := range checkpoints {
		ckSeq[c.Seq] = true
		timeAt[c.Seq+1] = true
	}
	hashAt := map[int64]string{} // hashes at checkpoint seqs
	times := map[int64]time.Time{}

	// 1. the chain
	prevHash := Genesis(tx.Tenant())
	if from > 1 {
		prev, err := tx.AuditEventBySeq(from - 1)
		switch {
		case errors.Is(err, store.ErrNotFound):
			add(ExitSeqGap, "seq_gap", from-1, "event %d (before the range) is missing", from-1)
			prevHash = ""
		case err != nil:
			return r, err
		default:
			prevHash = prev.Hash
		}
	}
	expect := from
	for {
		page, err := tx.AuditEventsRange(expect, to, verifyPage)
		if err != nil {
			return r, err
		}
		for _, e := range page {
			gap := false
			switch {
			case e.Seq > expect:
				gap = true
				if e.Seq == expect+1 {
					add(ExitSeqGap, "seq_gap", expect, "event %d is missing", expect)
				} else {
					add(ExitSeqGap, "seq_gap", expect, "events %d..%d are missing", expect, e.Seq-1)
				}
			case e.Seq < expect:
				add(ExitSeqGap, "seq_duplicate", e.Seq, "seq %d appears more than once", e.Seq)
				continue
			}
			if r.Events == 0 {
				r.FirstSeq = e.Seq
			}
			r.Events++
			r.LastSeq = e.Seq
			if e.TenantID != tx.Tenant() {
				add(ExitHashMismatch, "wrong_tenant", e.Seq, "event belongs to tenant %s", e.TenantID)
			}
			if got, err := EventHash(e); err != nil {
				add(ExitHashMismatch, "unhashable", e.Seq, "event cannot be hashed: %v", err)
			} else if got != e.Hash {
				add(ExitHashMismatch, "hash_mismatch", e.Seq, "stored hash %.12s… but the fields hash to %.12s… (row edited)", e.Hash, got)
			}
			if !gap && prevHash != "" && e.PrevHash != prevHash {
				add(ExitHashMismatch, "broken_link", e.Seq, "prev_hash %.12s… does not match the previous event's hash %.12s…", e.PrevHash, prevHash)
			}
			if ckSeq[e.Seq] {
				hashAt[e.Seq] = e.Hash
			}
			if timeAt[e.Seq] {
				times[e.Seq] = e.OccurredAt
			}
			prevHash = e.Hash
			expect = e.Seq + 1
		}
		if len(page) < verifyPage {
			break
		}
	}
	end := to
	if end == 0 || end > head.LastSeq {
		end = head.LastSeq
	}
	if expect <= end {
		add(ExitSeqGap, "seq_gap", expect, "events %d..%d are missing (the chain head is at %d)", expect, end, head.LastSeq)
	}
	if (to == 0 || to >= head.LastSeq) && head.LastSeq > 0 && r.LastSeq == head.LastSeq && prevHash != head.LastHash {
		add(ExitHashMismatch, "head_mismatch", head.LastSeq, "the chain head's hash does not match the last event")
	}
	if r.LastSeq > head.LastSeq {
		add(ExitSeqGap, "beyond_head", r.LastSeq, "events exist after the chain head (%d)", head.LastSeq)
	}

	// 2. checkpoints
	r.Checkpoints = len(checkpoints)
	var newestAnchored int64
	for _, c := range checkpoints {
		p, _, err := VerifyCheckpointJWS(c.JWS, o.Keys)
		switch {
		case err != nil:
			add(ExitCheckpointInvalid, "checkpoint_signature", c.Seq, "%v", err)
			continue
		case p.TID != tx.Tenant().String() || p.Seq != c.Seq || p.HeadHash != c.HeadHash:
			add(ExitCheckpointInvalid, "checkpoint_payload", c.Seq, "signed payload (tid %s, seq %d, head %.12s…) does not match the checkpoint row",
				p.TID, p.Seq, p.HeadHash)
			continue
		}
		if h, ok := hashAt[c.Seq]; !ok {
			add(ExitSeqGap, "checkpoint_event_missing", c.Seq, "the event a checkpoint certifies is missing")
		} else if h != c.HeadHash {
			add(ExitHashMismatch, "checkpoint_hash", c.Seq, "the event's hash differs from the signed checkpoint (chain rewritten)")
		}
		// 3. anchors
		if o.Anchors != nil {
			if !o.Anchors.Has(tx.Tenant().String(), c.Seq, c.JWS) {
				add(ExitAnchorMissing, "anchor_missing", c.Seq, "checkpoint not found in the anchor source (or anchored with a different JWS)")
				continue
			}
			r.Anchored++
			newestAnchored = max(newestAnchored, c.Seq)
		}
	}
	if o.Anchors != nil && !o.Now.IsZero() {
		// the oldest event not covered by an anchored checkpoint
		s := max(newestAnchored+1, from)
		if t, ok := times[s]; ok && s <= r.LastSeq && o.Now.Sub(t) > StaleAfter {
			add(ExitStaleAnchoring, "stale_anchoring", s, "event %d is %s old and no anchored checkpoint covers it",
				s, o.Now.Sub(t).Round(time.Second))
		}
	}
	switch {
	case r.ExitCode != 0:
		r.Result = "failed"
	case len(r.Problems) > 0:
		r.Result = "warning"
	default:
		r.Result = "ok"
	}
	return r, nil
}
