package admin

import "unicode"

// blankCommit reports whether a policy repository commit label shows nothing: it is empty, or made only of white
// space, control characters and invisible characters: format characters (zero width space, joiners, byte order
// mark), the other default-ignorable code points (Hangul filler U+3164 and U+FFA0, combining grapheme joiner
// U+034F), variation selectors and the braille blank U+2800. A label like that reads as empty in the approvals
// inbox, so the as-code apply routes refuse it like "".
func blankCommit(s string) bool {
	for _, r := range s {
		if !unicode.IsSpace(r) && !unicode.IsControl(r) && !unicode.Is(unicode.Cf, r) &&
			!unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) && !unicode.Is(unicode.Variation_Selector, r) && r != '\u2800' {
			return false
		}
	}
	return true
}
