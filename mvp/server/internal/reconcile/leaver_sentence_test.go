package reconcile

import (
	"fmt"
	"strings"
	"testing"
)

// The RF-06b cause sentence leads with the finding's count (accounts), not
// the number that left before the grace period (#140).
func TestLeaverSentence(t *testing.T) {
	cases := []struct {
		name                          string
		hits, old, onlyHere, firstDay int
		want                          string
	}{
		{"all past grace, shared", 3, 3, 0, 20, "3 accounts of people who left more than 14 days ago are still enabled in Okta."},
		{"all past grace, only here", 2, 2, 2, 20, "2 accounts of people who left more than 14 days ago are still enabled in Okta, and only here: the leaver process does not cover this system."},
		{"none past grace (the #140 case)", 2, 0, 0, 3, "2 accounts of people who left are still enabled in Okta (0 left more than 14 days ago)."},
		{"some past grace", 5, 2, 1, 30, "5 accounts of people who left are still enabled in Okta (2 left more than 14 days ago)."},
		{"single", 1, 1, 1, 20, "Oren left 20 days ago and is still active in Okta. Every other account was disabled: the leaver process does not cover this system."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := leaverSentence("Okta", "Oren", tc.firstDay, tc.hits, tc.old, tc.onlyHere, 14)
			if got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
			if tc.hits > 1 && !strings.HasPrefix(got, fmt.Sprintf("%d accounts", tc.hits)) {
				t.Errorf("sentence does not lead with the finding count %d: %q", tc.hits, got)
			}
		})
	}
}
