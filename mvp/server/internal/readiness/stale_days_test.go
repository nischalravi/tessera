package readiness

import "testing"

// The account staleness threshold is the stricter of the connection's stale_days and the tenant's people threshold.
func TestStaleDays(t *testing.T) {
	for _, tc := range []struct {
		name               string
		conn, tenant, want int
	}{
		{"connection unset", 0, 90, 90},
		{"tenant shorter", 90, 60, 60},
		{"connection shorter", 45, 90, 45},
		{"tenant longer never loosens", 90, 3650, 90},
		{"equal", 90, 90, 90},
	} {
		if got := staleDays(tc.conn, tc.tenant); got != tc.want {
			t.Errorf("%s: staleDays(%d, %d) = %d, want %d", tc.name, tc.conn, tc.tenant, got, tc.want)
		}
	}
}
