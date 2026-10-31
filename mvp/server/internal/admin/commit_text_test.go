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
		// visually blank characters outside category Cf (issue #772)
		{"hangul filler", "\u3164", true},
		{"halfwidth hangul filler", "\uffa0", true},
		{"hangul choseong and jungseong fillers", "\u115f\u1160", true},
		{"braille blank", "\u2800", true},
		{"combining grapheme joiner", "\u034f", true},
		{"variation selector", "\ufe0f", true},
		{"variation selector supplement", "\U000e0100", true},
		{"mixed invisible and filler", " \u200b\u3164\u2800\u2060", true},
		{"filler then text", "\u3164x", false},
		{"braille text", "\u2801", false},
		{"emoji with variation selector", "\u2764\ufe0f", false},
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
