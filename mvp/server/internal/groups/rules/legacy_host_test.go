package rules_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/rules"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A webhook rule stored before the ASCII-host rule (#944) can still be disabled or renamed while its URL is unchanged; a
// changed URL, or enabling it, gets the full check (#953).
func TestUpdate_LegacyNonASCIIHost(t *testing.T) {
	const legacy = "https://höoks.example.com/x"
	cases := []struct {
		name     string
		disabled bool
		url      string
		enabled  bool
		refused  bool
	}{
		{"disable", false, legacy, false, false},
		{"rename enabled", false, legacy, true, false},
		{"rename disabled", true, legacy, false, false},
		{"enable", true, legacy, true, true},
		{"other non-ASCII host", false, "https://göod.example.com/x", true, true},
		{"other non-ASCII host while disabling", false, "https://göod.example.com/x", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.withHTTP()
			h := newHook(t)
			s := onGroup(w.gB, rules.TrigDirectAdded, rules.ActWebhook, rules.Params{URL: h.srv.URL})
			rule, _ := w.create(w.admin, s)
			// the row as an earlier version stored it
			w.in(func(c *store.TenantTx) {
				r, err := rules.Get(c, rule.ID)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := json.Marshal(rules.Params{URL: legacy})
				r.Params, r.Enabled = string(b), !tc.disabled
				if err := c.UpdateGrpRule(r); err != nil {
					t.Fatal(err)
				}
			})
			s.Name, s.Enabled, s.Params.URL = "renamed", tc.enabled, tc.url
			err := w.inErr(func(c *store.TenantTx) error {
				_, _, err := rules.Update(w.rulesEnv(c, w.admin), rule.ID, s, false)
				return err
			})
			if tc.refused != (err != nil) || (err != nil && !strings.Contains(err.Error(), "must be ASCII")) {
				t.Fatalf("refused=%v, got %v", tc.refused, err)
			}
		})
	}
}
