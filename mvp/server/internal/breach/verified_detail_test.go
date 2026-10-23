package breach

import (
	"strings"
	"testing"
)

// The breach evidence must not overstate what a rotation re-read observed.
func TestVerifiedDetail(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"evidence":"age_and_last_use"}`, "disabled and unused"},
		{`{"evidence":"old_credential_absent"}`, "gone"},
		{`{"evidence":"age_only"}`, "only the old credential's age"},
		{`{}`, "without evidence detail"},
		{`not json`, "without evidence detail"},
	} {
		if got := verifiedDetail(tc.in); !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want it to contain %q", tc.in, got, tc.want)
		}
	}
	if d := verifiedDetail(`{"evidence":"age_only"}`); strings.Contains(d, "showed the old credential disabled") {
		t.Errorf("age_only overstates the evidence: %q", d)
	}
}
