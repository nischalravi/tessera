package config_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

// TestLoad_PolicyDiffTimeout: the blast-radius preview's own deadline (issue #766) defaults to 90s and is range-checked.
func TestLoad_PolicyDiffTimeout(t *testing.T) {
	for _, tc := range []struct {
		v    string
		ok   bool
		want time.Duration
	}{
		{"", true, 90 * time.Second},
		{"2m", true, 2 * time.Minute},
		{"45", true, 45 * time.Second},
		{"5s", true, 5 * time.Second},
		{"4s", false, 0},
		{"6m", false, 0},
		{"0s", false, 0},
		{"soon", false, 0},
	} {
		for name, base := range map[string]map[string]string{"prod": safeProd(), "dev": {"TESSERA_ENV": "dev"}} {
			e := base
			if tc.v != "" {
				e = with(base, "TESSERA_POLICY_DIFF_TIMEOUT", tc.v)
			}
			got, err := config.Load(env(e))
			if (err == nil) != tc.ok {
				t.Errorf("%s %q: err %v, want ok=%v", name, tc.v, err, tc.ok)
			}
			if tc.ok && got.PolicyDiffTimeout != tc.want {
				t.Errorf("%s %q: %s, want %s", name, tc.v, got.PolicyDiffTimeout, tc.want)
			}
		}
	}
}
