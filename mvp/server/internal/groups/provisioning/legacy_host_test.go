package provisioning

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A provisioner stored before the ASCII-host rule (#944) can still be paused or renamed while its target URL is unchanged;
// a changed URL, or taking it out of pause, gets the full check (#953).
func TestUpdate_LegacyNonASCIIHost(t *testing.T) {
	cfg := func(host string) map[string]any {
		return map[string]any{"target": map[string]any{"base_url": "https://" + host + "/scim/v2"}}
	}
	str := func(s string) *string { return &s }
	cases := []struct {
		name    string
		paused  bool
		in      func() UpdateInput
		refused bool
	}{
		{"pause", false, func() UpdateInput { return UpdateInput{Mode: str(store.ProvModePaused)} }, false},
		{"rename", false, func() UpdateInput { return UpdateInput{Name: str("renamed")} }, false},
		{"rename paused", true, func() UpdateInput { return UpdateInput{Name: str("renamed")} }, false},
		{"same config resent while pausing", false, func() UpdateInput {
			return UpdateInput{Mode: str(store.ProvModePaused), Config: scimConfig(cfg("scïm.example.com"))}
		}, false},
		{"resume", true, func() UpdateInput { return UpdateInput{Mode: str(store.ProvModeAdopt)} }, true},
		{"other host", false, func() UpdateInput { return UpdateInput{Config: scimConfig(cfg("göod.example.com"))} }, true},
		{"other host while pausing", false, func() UpdateInput {
			return UpdateInput{Mode: str(store.ProvModePaused), Config: scimConfig(cfg("göod.example.com"))}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := newHarness(t, 1)
			p, _ := x.prov("legacy", "")
			// the row as an earlier version stored it
			x.must(func(e model.Env) error {
				p.Config = scimConfig(cfg("scïm.example.com"))
				if tc.paused {
					p.Mode = store.ProvModePaused
				}
				return e.Tx.UpdateProvisioner(p, x.now)
			})
			var err error
			x.must(func(e model.Env) error {
				cur, gerr := e.Tx.Provisioner(p.ID)
				if gerr != nil {
					return gerr
				}
				in := tc.in()
				in.Version = cur.Version
				_, err = x.svc.Update(e.Tx, x.now, "t", p.ID, in)
				return nil
			})
			if tc.refused != (err != nil) || (err != nil && !strings.Contains(err.Error(), "must be ASCII")) {
				t.Fatalf("refused=%v, got %v", tc.refused, err)
			}
		})
	}
}
