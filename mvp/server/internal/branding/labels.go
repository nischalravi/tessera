package branding

import (
	"slices"
	"strings"
	"unicode"
)

// Term is a word of the product a tenant can rename (Admin > Branding & labels). Key is the English word the UI uses.
type Term struct {
	Key   string `json:"key"`
	Hint  string `json:"hint"`
	Plain string `json:"default"`
}

// Terms are the words that can be renamed. The UI replaces them, singular and plural, in the navigation and the page
// titles; the API never accepts any other key, so the stored object cannot grow without bound.
var Terms = []Term{
	{"entitlement", "A permission a group or role carries in a target system.", "entitlement"},
	{"group", "A set of people that holds access together.", "group"},
	{"access review", "A campaign in which reviewers keep or revoke access.", "access review"},
	{"guest", "A person from outside the organization.", "guest"},
	{"application", "A system Tessera reads from or writes to.", "application"},
}

// MaxLabel is the longest label, in characters.
const MaxLabel = 40

// Labels validates a renamed-terms object: known keys, plain-text values of 1 to MaxLabel characters. A value equal to
// its key is the default and is dropped.
func Labels(in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range in {
		if !slices.ContainsFunc(Terms, func(t Term) bool { return t.Key == k }) {
			return nil, refuse("invalid_label_term", "%q is not a term that can be renamed", k)
		}
		v = strings.Join(strings.Fields(v), " ")
		if v == "" || len([]rune(v)) > MaxLabel {
			return nil, refuse("invalid_label", "the label for %q is 1 to %d characters", k, MaxLabel)
		}
		for _, r := range v {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '-' && r != '\'' && r != '&' {
				return nil, refuse("invalid_label", "the label for %q can hold letters, digits, spaces, hyphens, & and apostrophes", k)
			}
		}
		if !strings.EqualFold(v, k) {
			out[k] = v
		}
	}
	return out, nil
}
