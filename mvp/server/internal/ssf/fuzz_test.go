package ssf

import (
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// FuzzParseSET: ParseSET never panics, and whatever it accepts carries the
// claims it was told to require.
func FuzzParseSET(f *testing.F) {
	sg := newSigner(f, jose.ES256, "k1")
	rs := newSigner(f, jose.RS256, "k2")
	keys := []Key{sg.jwk, rs.jwk}
	valid := sg.sign(f, claimsFor(nil))
	f.Add(valid)
	f.Add(rs.sign(f, claimsFor(nil)))
	f.Add(sg.sign(f, claimsFor(func(c map[string]any) {
		c["events"] = map[string]any{EventSessionRevoked: map[string]any{"subject": map[string]any{"format": "complex",
			"user": map[string]any{"format": "email", "email": "a@b.example"}}}}
	})))
	f.Add(b64(`{"alg":"none"}`) + "." + b64(`{"iss":"x"}`) + ".")
	f.Add(strings.Join(strings.Split(valid, ".")[:2], ".") + ".")
	f.Add("..")
	f.Add("")
	f.Add(`{"payload":"e30","signatures":[]}`)
	f.Fuzz(func(t *testing.T, raw string) {
		set, err := ParseSET(raw, keys, expect())
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("error is not an *Error: %T %v", err, err)
			}
			return
		}
		if set.Issuer != testIssuer || set.JTI == "" || set.EventType == "" || set.IssuedAt.After(expect().Now.Add(DefaultSkew)) ||
			expect().Now.Sub(set.IssuedAt) > DefaultMaxAge || (set.ExpiresAt != nil && !set.ExpiresAt.After(expect().Now)) {
			t.Fatalf("accepted a SET that breaks the rules: %+v", set)
		}
		_ = set.Subject.Label()
	})
}
