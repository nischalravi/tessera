package rotation

import (
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	created := now.Add(-100 * 24 * time.Hour)
	disabled := now.Add(-2 * time.Hour)
	before, after := disabled.Add(-time.Hour), disabled.Add(time.Minute)
	iam := Capabilities{CanDisable: true, ReportsLastUsed: true}
	vault := Capabilities{CanDisable: false}
	tests := map[string]struct {
		obs      Observation
		caps     Capabilities
		disabled *time.Time
		verdict  string
		evidence string
		ageDays  int // -1: none
	}{
		"disabled and unused since":      {Observation{Exists: true, CreatedAt: &created, LastUsedAt: &before, LastUsedKnown: true}, iam, &disabled, VerdictOK, EvidenceAgeAndLastUse, 100},
		"never used":                     {Observation{Exists: true, CreatedAt: &created, LastUsedKnown: true}, iam, &disabled, VerdictOK, EvidenceAgeAndLastUse, 100},
		"still active after disabling":   {Observation{Exists: true, Active: true, CreatedAt: &created, LastUsedKnown: true}, iam, &disabled, VerdictStillActive, EvidenceAgeAndLastUse, 100},
		"used after disabling":           {Observation{Exists: true, CreatedAt: &created, LastUsedAt: &after, LastUsedKnown: true}, iam, &disabled, VerdictUsedAfterDisable, EvidenceAgeAndLastUse, 100},
		"no creation time":               {Observation{Exists: true, LastUsedKnown: true}, iam, &disabled, VerdictMissingEvidence, EvidenceAgeOnly, -1},
		"provider cannot disable":        {Observation{Exists: true, Active: true, CreatedAt: &created}, vault, &disabled, VerdictOK, EvidenceAgeOnly, 100},
		"cannot disable, used after":     {Observation{Exists: true, Active: true, CreatedAt: &created, LastUsedAt: &after, LastUsedKnown: true}, Capabilities{ReportsLastUsed: true}, &disabled, VerdictUsedAfterDisable, EvidenceAgeAndLastUse, 100},
		"last use unknown is not a use":  {Observation{Exists: true, CreatedAt: &created, LastUsedAt: &after}, iam, &disabled, VerdictOK, EvidenceAgeOnly, 100},
		"already gone":                   {Observation{}, iam, &disabled, VerdictOK, EvidenceAbsent, -1},
		"creation in the future is zero": {Observation{Exists: true, CreatedAt: &after2, LastUsedKnown: true}, iam, &disabled, VerdictOK, EvidenceAgeAndLastUse, 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			v := Verify(tc.obs, tc.caps, tc.disabled, now)
			if v.Verdict != tc.verdict || v.Evidence != tc.evidence {
				t.Errorf("verdict %s / evidence %s, want %s / %s (%s)", v.Verdict, v.Evidence, tc.verdict, tc.evidence, v.Detail)
			}
			switch {
			case tc.ageDays < 0 && v.OldAgeDays != nil:
				t.Errorf("age %d, want none", *v.OldAgeDays)
			case tc.ageDays >= 0 && (v.OldAgeDays == nil || *v.OldAgeDays != tc.ageDays):
				t.Errorf("age %v, want %d", v.OldAgeDays, tc.ageDays)
			}
			if !v.CheckedAt.Equal(now) {
				t.Errorf("checked at %v", v.CheckedAt)
			}
		})
	}
}

var after2 = time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
