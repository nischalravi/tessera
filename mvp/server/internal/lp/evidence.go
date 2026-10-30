package lp

import (
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Evidence and metrics of the loop (issue #666, LP-10; design docs/design/least-privilege-loop.md section 7).
//
// The evidence of a revocation is computed from the rows the loop keeps anyway (the revocation, its events, the
// false-positive label and the denials that restored it), not copied into a table of its own: there is no second
// record to drift from the first. The revocation row holds what was true when the candidate was built (usage window,
// confidence and its reasons, the used calls the right-size keeps, the simulation diff, the digests) and is never
// rewritten; the events and labels are append-only. The record's SHA-256 is in the audit event of its transition to
// revoked, finalized and restored, so for a finalized or restored revocation (terminal) the digest of the exported
// record equals the one in the hash chain.

// EvidenceSchema identifies the record layout.
const EvidenceSchema = "tessera.lp-evidence/1"

// Evidence is the record of one revocation.
type Evidence struct {
	Schema       string `json:"schema"`
	RevocationID string `json:"revocation_id"`
	State        string `json:"state"`
	Principal    string `json:"principal"`
	PolicyARN    string `json:"policy_arn"`
	Kind         string `json:"kind"`
	AccountID    string `json:"account_id"`
	ConnectorID  string `json:"connector_id"`

	// UsageWindow is how long the removed access went unused and the snapshot it was judged against.
	UsageWindow EvidenceWindow `json:"usage_window"`
	// Confidence is the level and the reasons recorded when the candidate was built.
	Confidence json.RawMessage `json:"confidence"`
	// Verification is the evaluator's check of the right-size: the used calls it keeps and none it breaks.
	Verification json.RawMessage `json:"verification"`
	// Simulation is the summary of the simulated diff of the change (what the principals gain and lose).
	Simulation json.RawMessage `json:"simulation"`

	Approval EvidenceApproval `json:"approval"`
	Revoke   EvidenceRevoke   `json:"revoke"`
	// Reread is the verified re-read of the target after the change.
	Reread EvidenceReread `json:"reread"`

	Restore       *EvidenceRestore       `json:"restore,omitempty"`
	FalsePositive *EvidenceFalsePositive `json:"false_positive,omitempty"`
	FinalizedAt   string                 `json:"finalized_at,omitempty"`

	Timeline []EvidenceStep `json:"timeline"`
	// SHA256 is the digest of this record with SHA256 empty (the JSON as marshalled by this package).
	SHA256 string `json:"sha256"`
}

// EvidenceWindow is the usage window of a revocation.
type EvidenceWindow struct {
	UnusedDays int    `json:"unused_days"`
	SnapshotID string `json:"snapshot_id"`
	// AssessedAt is when the candidate was built: the window ends here.
	AssessedAt string `json:"assessed_at"`
}

// EvidenceApproval is who allowed the revocation and by which path.
type EvidenceApproval struct {
	// Path is auto (the policy in the access-as-code repository announced it) or staged (a person approved it).
	Path          string `json:"path"`
	Eligibility   string `json:"eligibility"`
	ApprovedBy    string `json:"approved_by,omitempty"`
	ApprovedAt    string `json:"approved_at,omitempty"`
	AnnounceUntil string `json:"announce_until,omitempty"`
	// Detail is the detail of the announcement event: the policy reference for the auto path.
	Detail string `json:"detail,omitempty"`
}

// EvidenceRevoke is the change itself.
type EvidenceRevoke struct {
	OpID            string `json:"op_id,omitempty"`
	ExecutedAt      string `json:"executed_at,omitempty"`
	RevokedAt       string `json:"revoked_at,omitempty"`
	CandidateSHA256 string `json:"candidate_sha256"`
	RestoreSHA256   string `json:"restore_sha256"`
}

// EvidenceReread says whether the target was read again after the change and held the candidate.
type EvidenceReread struct {
	Verified       bool   `json:"verified"`
	At             string `json:"at,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

// EvidenceRestore is a restore: what triggered it and how long it took.
type EvidenceRestore struct {
	Trigger        string           `json:"trigger"`
	RequestedAt    string           `json:"requested_at,omitempty"`
	RestoredAt     string           `json:"restored_at,omitempty"`
	OpID           string           `json:"op_id,omitempty"`
	LatencySeconds *int64           `json:"latency_seconds,omitempty"`
	Denials        []EvidenceDenial `json:"denials,omitempty"`
}

// EvidenceDenial is a denial event that led to the restore.
type EvidenceDenial struct {
	Source    string `json:"source"`
	EventID   string `json:"event_id"`
	Action    string `json:"action"`
	Resource  string `json:"resource,omitempty"`
	ArrivedAt string `json:"arrived_at"`
}

// EvidenceFalsePositive is the label of access that turned out to be needed.
type EvidenceFalsePositive struct {
	Source     string `json:"source"`
	Ref        string `json:"ref,omitempty"`
	LabelledAt string `json:"labelled_at"`
}

// EvidenceStep is one transition of the revocation.
type EvidenceStep struct {
	From   string `json:"from,omitempty"`
	To     string `json:"to"`
	Actor  string `json:"actor"`
	Detail string `json:"detail,omitempty"`
	At     string `json:"at"`
}

// storedEvidence is the JSON the candidate carries (internal/api lp.go, lpPropose).
type storedEvidence struct {
	Confidence   json.RawMessage `json:"confidence"`
	Verification json.RawMessage `json:"verification"`
	DiffSummary  json.RawMessage `json:"diff_summary"`
}

// raw returns v when it is a JSON object, and {} otherwise: the record always has the same keys.
func raw(v json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(v, &m) != nil || m == nil {
		return json.RawMessage(`{}`)
	}
	return v
}

func rtp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return store.RT(*t)
}

// EvidenceFor builds the evidence record of one revocation. store.ErrNotFound when there is none.
func EvidenceFor(tx *store.TenantTx, id string) (*Evidence, error) {
	r, err := tx.LPRevocation(id)
	if err != nil {
		return nil, err
	}
	return BuildEvidence(tx, r)
}

// BuildEvidence builds the record of r from what the tenant's tables hold now.
func BuildEvidence(tx *store.TenantTx, r *store.LPRevocation) (*Evidence, error) {
	var se storedEvidence
	_ = json.Unmarshal([]byte(r.Evidence), &se) // an unreadable blob leaves the sections empty
	e := &Evidence{Schema: EvidenceSchema, RevocationID: r.ID, State: r.State, Principal: r.Principal, PolicyARN: r.PolicyARN,
		Kind: r.Kind, AccountID: r.AccountID, ConnectorID: r.ConnectorID,
		UsageWindow:  EvidenceWindow{UnusedDays: r.UnusedDays, SnapshotID: r.SnapshotID, AssessedAt: store.RT(r.CreatedAt)},
		Confidence:   raw(se.Confidence),
		Verification: raw(se.Verification),
		Simulation:   raw(se.DiffSummary),
		Approval: EvidenceApproval{Path: "staged", Eligibility: r.Eligibility, ApprovedBy: r.ApprovedBy, ApprovedAt: rtp(r.ApprovedAt),
			AnnounceUntil: rtp(r.AnnounceUntil)},
		Revoke: EvidenceRevoke{OpID: r.OpID, ExecutedAt: rtp(r.ExecutedAt), RevokedAt: rtp(r.RevokedAt),
			CandidateSHA256: r.CandidateSHA256, RestoreSHA256: r.RestoreSHA256},
		Reread:      EvidenceReread{ExpectedSHA256: r.CandidateSHA256},
		FinalizedAt: rtp(r.FinalizedAt),
		Timeline:    []EvidenceStep{},
	}
	if r.ApprovedBy == ActorAutoPolicy {
		e.Approval.Path = "auto"
	}
	evs, err := tx.LPEvents(r.ID)
	if err != nil {
		return nil, err
	}
	for _, ev := range evs {
		e.Timeline = append(e.Timeline, EvidenceStep{From: ev.From, To: ev.To, Actor: ev.Actor, Detail: ev.Detail, At: store.RT(ev.CreatedAt)})
		switch ev.To {
		case store.LPAnnounced:
			e.Approval.Detail = ev.Detail
		case store.LPRevoked:
			// the loop enters revoked only after the target was read again and held the candidate
			e.Reread.Verified, e.Reread.At = true, store.RT(ev.CreatedAt)
		}
	}
	if r.RestoreTrigger != "" || r.RestoreRequestedAt != nil || r.RestoredAt != nil {
		rs := &EvidenceRestore{Trigger: r.RestoreTrigger, RequestedAt: rtp(r.RestoreRequestedAt), RestoredAt: rtp(r.RestoredAt), OpID: r.RestoreOpID}
		if r.RestoreRequestedAt != nil && r.RestoredAt != nil {
			lat := int64(r.RestoredAt.Sub(*r.RestoreRequestedAt).Seconds())
			rs.LatencySeconds = &lat
		}
		ds, err := tx.LPDenialsFor(r.ID)
		if err != nil {
			return nil, err
		}
		for _, d := range ds {
			rs.Denials = append(rs.Denials, EvidenceDenial{Source: d.Source, EventID: d.EventID, Action: d.Action, Resource: d.Resource,
				ArrivedAt: store.RT(d.ArrivedAt)})
		}
		e.Restore = rs
	}
	fp, err := tx.LPFalsePositive(r.ID)
	switch {
	case err == nil:
		e.FalsePositive = &EvidenceFalsePositive{Source: fp.Source, Ref: fp.Ref, LabelledAt: store.RT(fp.CreatedAt)}
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	e.SHA256 = seal.SHA256Hex(b)
	return e, nil
}

// EvidenceBetween builds the records of the revocations carried out in [from, to), oldest first, at most limit.
func EvidenceBetween(tx *store.TenantTx, from, to time.Time, limit int) ([]*Evidence, error) {
	rs, err := tx.LPExecutedBetween(from, to, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*Evidence, 0, len(rs))
	for _, r := range rs {
		e, err := BuildEvidence(tx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// ---------------------------------------------------------------- metrics

// MetricsLevel is one confidence level's outcomes over the window.
type MetricsLevel struct {
	Confidence     string  `json:"confidence"`
	Revoked        int     `json:"revoked"`
	Restored       int     `json:"restored"`
	RestorePercent float64 `json:"restore_percent"`
	FalsePositives int     `json:"false_positives"`
	// FalsePositivePercent is restores and JIT re-requests labelled false positives, over revocations carried out.
	FalsePositivePercent float64 `json:"false_positive_percent"`
	// Review: the level is high and over HighFalsePositivePercent: the rule is reviewed by a person.
	Review bool `json:"review"`
}

// Metrics are what the dashboard shows.
type Metrics struct {
	WindowDays int    `json:"window_days"`
	From       string `json:"from"`
	To         string `json:"to"`
	// Truncated: more than store.LPEvidenceMaxRows revocations fell in the window; the counts cover the oldest.
	Truncated bool `json:"truncated"`
	Executed  int  `json:"executed"`
	// UnusedPermissionsRemoved sums the permissions the evaluator's check says the right-size removed, over the revocations whose removal stands
	// (revoked or finalized); a restored or failed one removes nothing now.
	UnusedPermissionsRemoved int `json:"unused_permissions_removed"`
	Auto                     int `json:"auto"`
	Staged                   int `json:"staged"`
	// FalsePositivePercent is over every level together.
	FalsePositivePercent float64        `json:"false_positive_percent"`
	Levels               []MetricsLevel `json:"levels"`
	ByState              map[string]int `json:"by_state"`
	// MedianRestoreSeconds is the median time from a restore being requested to its verified completion; nil
	// when nothing was restored in the window. RestoresWithinSLO counts those inside RestoreSLO.
	MedianRestoreSeconds *int64 `json:"median_restore_seconds"`
	Restores             int    `json:"restores"`
	RestoresWithinSLO    int    `json:"restores_within_slo"`
	RestoreSLOSeconds    int64  `json:"restore_slo_seconds"`
}

// MetricsFor computes the metrics of the revocations carried out in the days before now.
func MetricsFor(tx *store.TenantTx, now time.Time, days int) (*Metrics, error) {
	from := now.AddDate(0, 0, -days)
	rs, err := tx.LPExecutedBetween(from, now.Add(time.Microsecond), store.LPEvidenceMaxRows+1)
	if err != nil {
		return nil, err
	}
	m := &Metrics{WindowDays: days, From: store.RT(from), To: store.RT(now), ByState: map[string]int{}, Levels: []MetricsLevel{},
		RestoreSLOSeconds: int64(RestoreSLO.Seconds())}
	if len(rs) > store.LPEvidenceMaxRows {
		rs, m.Truncated = rs[:store.LPEvidenceMaxRows], true
	}
	levels := map[string]*MetricsLevel{"high": {Confidence: "high"}, "medium": {Confidence: "medium"}}
	var lat []int64
	for _, r := range rs {
		m.Executed++
		m.ByState[r.State]++
		if r.ApprovedBy == ActorAutoPolicy {
			m.Auto++
		} else {
			m.Staged++
		}
		if l := levels[r.Confidence]; l != nil {
			l.Revoked++
			if r.State == store.LPRestored || r.State == store.LPRestoring {
				l.Restored++
			}
		}
		if r.State == store.LPRevoked || r.State == store.LPFinalized {
			var se storedEvidence
			var v struct {
				Removed int `json:"removed"`
			}
			if json.Unmarshal([]byte(r.Evidence), &se) == nil && json.Unmarshal(se.Verification, &v) == nil {
				m.UnusedPermissionsRemoved += v.Removed
			}
		}
		if r.RestoreRequestedAt != nil && r.RestoredAt != nil {
			d := r.RestoredAt.Sub(*r.RestoreRequestedAt)
			lat = append(lat, int64(d.Seconds()))
			m.Restores++
			if d <= RestoreSLO {
				m.RestoresWithinSLO++
			}
		}
	}
	cal, err := tx.LPCalibration(from)
	if err != nil {
		return nil, err
	}
	var fps int
	for _, c := range cal {
		l := levels[c.Confidence]
		if l == nil {
			continue
		}
		l.FalsePositives = c.FalsePositives
		fps += c.FalsePositives
	}
	for _, name := range []string{"high", "medium"} {
		l := levels[name]
		if l.Revoked > 0 {
			l.RestorePercent = float64(l.Restored) * 100 / float64(l.Revoked)
			l.FalsePositivePercent = float64(l.FalsePositives) * 100 / float64(l.Revoked)
			l.Review = name == "high" && l.FalsePositives*100 > l.Revoked*HighFalsePositivePercent
		}
		m.Levels = append(m.Levels, *l)
	}
	if m.Executed > 0 {
		m.FalsePositivePercent = float64(fps) * 100 / float64(m.Executed)
	}
	if len(lat) > 0 {
		slices.Sort(lat)
		med := lat[len(lat)/2]
		if len(lat)%2 == 0 {
			med = (lat[len(lat)/2-1] + lat[len(lat)/2]) / 2
		}
		m.MedianRestoreSeconds = &med
	}
	return m, nil
}
