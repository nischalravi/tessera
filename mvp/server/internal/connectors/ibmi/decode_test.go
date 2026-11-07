package ibmi

import (
	"encoding/json"
	"strings"
	"testing"
)

// An unknown value nested past maxSkipDepth is a protocol error; one within it is skipped (review low, #886).
func TestSkipValueDepthCap(t *testing.T) {
	nest := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	for _, tc := range []struct {
		name string
		n    int
		ok   bool
	}{{"flat", 1, true}, {"at the cap", maxSkipDepth, true}, {"past the cap", maxSkipDepth + 1, false}, {"very deep", 100000, false}} {
		d := json.NewDecoder(strings.NewReader(nest(tc.n)))
		if err := skipValue(d); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok %t", tc.name, err, tc.ok)
		}
	}
}
