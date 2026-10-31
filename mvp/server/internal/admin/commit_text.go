package admin

import "unicode"

// blankCommit reports whether a policy repository commit label shows nothing: it is empty, or made only of white
// space, control characters and invisible format characters (zero width space, joiners, byte order mark). A label
// like that reads as empty in the approvals inbox, so the as-code apply routes refuse it like "".
func blankCommit(s string) bool {
	for _, r := range s {
		if !unicode.IsSpace(r) && !unicode.IsControl(r) && !unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
