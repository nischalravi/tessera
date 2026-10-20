package rotation

import (
	"time"
)

// Verdicts of the re-read of an old credential.
const (
	VerdictOK               = "ok"
	VerdictStillActive      = "still_active"
	VerdictUsedAfterDisable = "used_after_disable"
	VerdictMissingEvidence  = "missing_evidence"
)

// Evidence levels: what the provider let Tessera observe.
const (
	EvidenceAgeAndLastUse = "age_and_last_use"
	EvidenceAgeOnly       = "age_only"
	EvidenceAbsent        = "old_credential_absent"
)

// Verification is the recorded re-read of the old credential. It is stored on
// the job (JSON) and a job cannot be marked verified, or have its old
// credential deleted, without it.
type Verification struct {
	CheckedAt     time.Time  `json:"checked_at"`
	Verdict       string     `json:"verdict"`
	Evidence      string     `json:"evidence"`
	OldExists     bool       `json:"old_exists"`
	OldActive     bool       `json:"old_active"`
	OldCreatedAt  *time.Time `json:"old_created_at"`
	OldAgeDays    *int       `json:"old_age_days"`
	OldLastUsedAt *time.Time `json:"old_last_used_at"`
	LastUsedKnown bool       `json:"last_used_known"`
	DisabledAt    *time.Time `json:"disabled_at"`
	Detail        string     `json:"detail,omitempty"`
}

// Verify judges a re-read of the old credential. disabledAt is when the old
// credential was disabled (or, for a provider that cannot disable, when the
// grace period ended): a use after that point means a consumer did not move
// to the new credential, so deleting the old one would break it.
func Verify(obs Observation, caps Capabilities, disabledAt *time.Time, now time.Time) Verification {
	v := Verification{CheckedAt: now.UTC(), Verdict: VerdictOK, OldExists: obs.Exists, OldActive: obs.Active,
		OldCreatedAt: obs.CreatedAt, OldLastUsedAt: obs.LastUsedAt, LastUsedKnown: obs.LastUsedKnown,
		DisabledAt: disabledAt, Detail: obs.Detail}
	if obs.CreatedAt != nil {
		d := int(now.Sub(*obs.CreatedAt).Hours() / 24)
		if d < 0 {
			d = 0
		}
		v.OldAgeDays = &d
	}
	switch {
	case !obs.Exists:
		v.Evidence = EvidenceAbsent
		return v
	case obs.CreatedAt == nil:
		v.Verdict, v.Evidence = VerdictMissingEvidence, EvidenceAgeOnly
		v.Detail = "the provider did not report the old credential's creation time"
		return v
	case obs.Active && caps.CanDisable:
		v.Verdict = VerdictStillActive
		v.Detail = "the old credential is still active after it was disabled"
	case obs.LastUsedKnown && obs.LastUsedAt != nil && disabledAt != nil && obs.LastUsedAt.After(*disabledAt):
		v.Verdict = VerdictUsedAfterDisable
		v.Detail = "the old credential was used after the grace period; a consumer has not moved to the new one"
	}
	v.Evidence = EvidenceAgeOnly
	if obs.LastUsedKnown {
		v.Evidence = EvidenceAgeAndLastUse
	}
	return v
}
