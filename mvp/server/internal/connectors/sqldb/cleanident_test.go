package sqldb

import (
	"strings"
	"testing"
)

// A valid name comes back unchanged; any character outside the alphabet is refused.
func TestCleanIdent(t *testing.T) {
	for _, n := range []string{"alice", "A_b.c-d", "alice@db.example", "alice@%", "svc$1#x", "server:sysadmin", "0abc", strings.Repeat("a", 128)} {
		got, err := cleanIdent(n)
		if err != nil || got != n {
			t.Errorf("cleanIdent(%q) = %q, %v", n, got, err)
		}
	}
	for _, n := range []string{"", strings.Repeat("a", 129), "a b", `a"`, "a'", "a;", `a\b`, "a\x00", "a\n", "é", "аdmin", "a‮b", "ａ", "a`", "a]", "a(", "a/"} {
		if got, err := cleanIdent(n); err == nil {
			t.Errorf("cleanIdent(%q) = %q, want an error", n, got)
		}
	}
	// every byte of the alphabet is accepted, and nothing else is
	for r := rune(0); r < 0x250; r++ {
		_, err := cleanIdent("a" + string(r))
		if want := strings.ContainsRune(identAlphabet, r); (err == nil) != want {
			t.Errorf("rune %U: accepted=%v, in alphabet=%v", r, err == nil, want)
		}
	}
	// the alphabet and the allow-list agree
	for _, r := range identAlphabet {
		if !safeName.MatchString("a" + string(r)) {
			t.Errorf("%q is in the alphabet but not in safeName", r)
		}
	}
}
