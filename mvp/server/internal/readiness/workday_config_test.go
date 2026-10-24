package readiness

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
)

func TestWorkdayAPIVersionValidation(t *testing.T) {
	r, _ := template.MustDefault().Get("workday")
	for _, tc := range []struct {
		version string
		bad     bool
	}{
		{"", false}, {"v44.0", false}, {"v44", false}, {"v44.10", false}, {"v44.100", true}, {"44.0", true}, {"v44.0/../x", true}, {"v4444.0", true},
	} {
		cfg := ConnConfig{CorrelationKey: "employee_id", TenantHost: "wd5.myworkday.com", Interface: "get_workers", APIVersion: tc.version}
		got := false
		for _, e := range Validate(cfg, r) {
			if e.Field == "api_version" {
				got = true
			}
		}
		if got != tc.bad {
			t.Errorf("api_version %q: rejected=%v, want %v", tc.version, got, tc.bad)
		}
	}
}
