package admin

import "testing"

func TestBlankCommit(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		blank    bool
	}{
		{"empty", "", true},
		{"spaces", "   ", true},
		{"tab newline", "\t\n ", true},
		{"no-break space", "\u00a0", true},
		{"zero width space", "\u200b", true},
		{"word joiner", "\u2060", true},
		{"byte order mark", "\ufeff", true},
		{"mixed invisible", " \u200b\u200d\t", true},
		{"control", "\x00\x07", true},
		{"text", "fix", false},
		{"padded text", " x ", false},
		{"invisible then text", "\u200bx", false},
		{"non-latin text", "改善", false},
	} {
		if got := blankCommit(tc.in); got != tc.blank {
			t.Errorf("%s: blankCommit(%q) = %v, want %v", tc.name, tc.in, got, tc.blank)
		}
	}
}
