package breach

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// EvidenceVersion is the schema of the evidence export.
const EvidenceVersion = 1

// RotationJobEvidence is one rotation job of the plan's rotation run, as the
// auditor sees it: states and times, never a credential.
type RotationJobEvidence struct {
	ID           string          `json:"id"`
	SecretID     int64           `json:"secret_id"`
	State        string          `json:"state"`
	CreatedAt    time.Time       `json:"created_at"`
	HandedOverAt *time.Time      `json:"handed_over_at"`
	DisabledAt   *time.Time      `json:"disabled_at"`
	VerifiedAt   *time.Time      `json:"verified_at"`
	CompletedAt  *time.Time      `json:"completed_at"`
	Verification json.RawMessage `json:"verification,omitempty"`
	LastError    *string         `json:"last_error"`
}

// Evidence is the export of a plan: the response to the breach with the
// re-read of each credential. Body is what SHA256 covers.
type Evidence struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	SHA256      string    `json:"sha256"`
	Body        Body      `json:"evidence"`
}

// Body is the hashed part of an Evidence.
type Body struct {
	Plan         PlanEvidence          `json:"plan"`
	Report       Report                `json:"report"`
	RotationRun  *RotationRunEvidence  `json:"rotation_run"`
	RotationJobs []RotationJobEvidence `json:"rotation_jobs"`
	// Attestations are the two-admin requests that attested manual items (issue #538), whatever became of them.
	Attestations []AttestationEvidence `json:"attestations"`
}

// AttestationEvidence is one attestation request: who asked, who approved (empty until a second admin does) and
// what became of it. The ledger holds the same events.
type AttestationEvidence struct {
	ChangeID    string     `json:"change_id"`
	ItemID      string     `json:"item_id"`
	Status      string     `json:"status"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	ApprovedBy  string     `json:"approved_by"`
	ApprovedAt  *time.Time `json:"approved_at"`
	AppliedAt   *time.Time `json:"applied_at"`
	PayloadHash string     `json:"payload_hash"`
}

// attestationEvidence lists the plan's attestation requests, oldest first, naming both admins.
func attestationEvidence(tx *store.TenantTx, planID string) ([]AttestationEvidence, error) {
	changes, err := tx.AdminChanges()
	if err != nil {
		return nil, err
	}
	out := []AttestationEvidence{}
	for i := len(changes) - 1; i >= 0; i-- { // AdminChanges is newest first
		c := changes[i]
		var pl struct {
			PlanID string `json:"plan_id"`
		}
		if c.Type != ChangeType || json.Unmarshal(c.Payload, &pl) != nil || pl.PlanID != planID {
			continue
		}
		e := AttestationEvidence{ChangeID: c.ID.String(), ItemID: c.TargetID, Status: c.Status, RequestedBy: UserName(tx, c.RequestedBy),
			RequestedAt: c.RequestedAt, ApprovedAt: c.ApprovedAt, AppliedAt: c.AppliedAt, PayloadHash: c.PayloadHash}
		if c.ApprovedBy != nil {
			e.ApprovedBy = UserName(tx, *c.ApprovedBy)
		}
		out = append(out, e)
	}
	return out, nil
}

// UserName is the display name of a tenant user, or the id when it has none.
func UserName(tx *store.TenantTx, id uuid.UUID) string {
	if u, err := tx.PlatformUser(id); err == nil && u.DisplayName != "" {
		return u.DisplayName
	}
	return id.String()
}

// PlanEvidence is the plan's own record.
type PlanEvidence struct {
	ID          string     `json:"id"`
	Vendor      string     `json:"vendor"`
	Reason      string     `json:"reason"`
	Status      string     `json:"status"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedBy   *string    `json:"started_by"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

// RotationRunEvidence is the rotation bulk run the plan queued.
type RotationRunEvidence struct {
	ID          string    `json:"id"`
	Reason      string    `json:"reason"`
	PlanHash    string    `json:"plan_hash"`
	RequestedBy string    `json:"requested_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// Evidence builds the export of a plan. The ledger records the plan's events
// (breach.plan.created, started, verified, completed, item attested, and the
// rotation and revoke events of the work), so the export names them.
func (s *Service) Evidence(tx *store.TenantTx, id string, now time.Time) (*Evidence, error) {
	p, err := s.plan(tx, id)
	if err != nil {
		return nil, err
	}
	v, err := viewOf(tx, p)
	if err != nil {
		return nil, err
	}
	b := Body{Report: v.Report, RotationJobs: []RotationJobEvidence{}, Attestations: []AttestationEvidence{},
		Plan: PlanEvidence{ID: p.ID, Vendor: p.Vendor, Reason: p.Reason, Status: p.Status, CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt,
			StartedBy: p.StartedBy, StartedAt: p.StartedAt, CompletedAt: p.CompletedAt}}
	if p.BulkID != nil {
		bulk, err := tx.RotationBulk(*p.BulkID)
		if err != nil {
			return nil, err
		}
		b.RotationRun = &RotationRunEvidence{ID: bulk.ID, Reason: bulk.Reason, PlanHash: bulk.PlanHash, RequestedBy: bulk.RequestedBy, CreatedAt: bulk.CreatedAt}
		jobs, err := tx.RotationJobs(store.RotationJobFilter{BulkID: bulk.ID, Limit: 5000})
		if err != nil {
			return nil, err
		}
		for _, j := range jobs {
			je := RotationJobEvidence{ID: j.ID, SecretID: j.SecretID, State: j.State, CreatedAt: j.CreatedAt, HandedOverAt: j.HandedOverAt,
				DisabledAt: j.DisabledAt, VerifiedAt: j.VerifiedAt, CompletedAt: j.CompletedAt, LastError: j.LastError}
			if j.Verification != nil {
				je.Verification = json.RawMessage(*j.Verification)
			}
			b.RotationJobs = append(b.RotationJobs, je)
		}
	}
	if b.Attestations, err = attestationEvidence(tx, p.ID); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return &Evidence{Version: EvidenceVersion, GeneratedAt: now, SHA256: hex.EncodeToString(sum[:]), Body: b}, nil
}

// FileName is the download name of a plan's evidence.
func FileName(vendor, planID string) string {
	safe := make([]byte, 0, len(vendor))
	for _, c := range []byte(vendor) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			safe = append(safe, c)
		}
	}
	short := planID
	if len(short) > 8 {
		short = short[:8]
	}
	return "breach-" + string(safe) + "-" + short + "-evidence.json"
}
