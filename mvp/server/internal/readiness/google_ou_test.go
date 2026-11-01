package readiness

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

// TestValidateConn_GoogleOrgUnits: base_dns on a Google Workspace connection is
// a list of org unit paths (issue #594): optional, well formed, bounded; the
// message never echoes the input.
func TestValidateConn_GoogleOrgUnits(t *testing.T) {
	ok := ConnConfig{Customer: "my_customer"}
	many := make([]string, 51)
	for i := range many {
		many[i] = fmt.Sprintf("/ou%d", i)
	}
	for name, tc := range map[string]struct {
		ous  []string
		good bool
	}{
		"none":                {nil, true},
		"root":                {[]string{"/"}, true},
		"nested with a space": {[]string{"/Eng", "/Sales/EMEA West"}, true},
		"fifty":               {many[:50], true},
		"fifty one":           {many, false},
		"no leading slash":    {[]string{"Eng"}, false},
		"a DN":                {[]string{"OU=People,DC=example,DC=com"}, false},
		"empty":               {[]string{""}, false},
		"trailing slash":      {[]string{"/Eng/"}, false},
		"empty segment":       {[]string{"/Eng//Ops"}, false},
		"quote":               {[]string{"/Eng' OR 1=1"}, false},
		"backslash":           {[]string{`/Eng\x`}, false},
		"control character":   {[]string{"/Eng\nX"}, false},
		"too long":            {[]string{"/" + strings.Repeat("a", 256)}, false},
		"duplicate":           {[]string{"/Eng", "/Eng"}, false},
	} {
		cfg := ok
		cfg.BaseDNs = tc.ous
		var bad []FieldError
		for _, fe := range ValidateConnEnv(cfg, tmplOfID(t, "google"), "google", config.Prod) {
			if fe.Field == "base_dns" {
				bad = append(bad, fe)
				for _, in := range tc.ous {
					if len(in) > 3 && strings.Contains(fe.Msg, in) {
						t.Errorf("%s: message echoes the input: %q", name, fe.Msg)
					}
				}
			}
		}
		if (len(bad) == 0) != tc.good {
			t.Errorf("%s: base_dns errors = %v, want good=%v", name, bad, tc.good)
		}
	}
}
