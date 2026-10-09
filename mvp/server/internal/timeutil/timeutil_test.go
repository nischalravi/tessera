package timeutil

import (
	"testing"
	"time"
)

func TestDaysFloorsLikePython(t *testing.T) {
	base := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		d    time.Duration
		want int
	}{{0, 0}, {23 * time.Hour, 0}, {24 * time.Hour, 1}, {-time.Hour, -1}, {-24 * time.Hour, -1}, {-25 * time.Hour, -2}}
	for _, tc := range tests {
		if got := Days(base.Add(tc.d), base); got != tc.want {
			t.Errorf("Days(%v) = %d, want %d", tc.d, got, tc.want)
		}
	}
}

func TestISOAndParse(t *testing.T) {
	tests := []struct {
		t    time.Time
		want string
	}{
		{time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "2026-01-02T03:04:05"},
		{time.Date(2026, 1, 2, 3, 4, 5, 120000, time.UTC), "2026-01-02T03:04:05.000120"},
	}
	for _, tc := range tests {
		if got := ISO(tc.t); got != tc.want {
			t.Errorf("ISO = %q, want %q", got, tc.want)
		}
		back, err := ParseDB(DB(tc.t))
		if err != nil || !back.Equal(tc.t) {
			t.Errorf("DB round trip = %v %v", back, err)
		}
	}
	if _, err := ParseDB("yesterday"); err == nil {
		t.Error("bad timestamp should fail")
	}
}

func TestDeltaMatchesCPythonTimedelta(t *testing.T) {
	tests := []struct {
		v    float64
		unit int64
		want time.Duration
	}{
		{1.5, MicrosPerHour, 90 * time.Minute},
		{2, MicrosPerDay, 48 * time.Hour},
		// expected values from CPython's timedelta(days=v); literals are the exact
		// doubles Python prints (Go constant arithmetic would round differently)
		{1e-12, MicrosPerDay, 0},
		{5.787037037037037e-12, MicrosPerDay, 0},
		{1.736111111111111e-11, MicrosPerDay, 2 * time.Microsecond},
		{2.8935185185185184e-11, MicrosPerDay, 2 * time.Microsecond},
		{3.472222222222222e-06, MicrosPerDay, 300 * time.Millisecond},
		{7.123456789, MicrosPerDay, 615466666570 * time.Microsecond},
	}
	for _, tc := range tests {
		if got := Delta(tc.v, tc.unit); got != tc.want {
			t.Errorf("Delta(%v) = %v, want %v", tc.v, got, tc.want)
		}
	}
	if Round(0.125, 2) != 0.12 || Round(2.675, 2) != 2.67 || Round(36.04, 1) != 36.0 {
		t.Error("Round should match Python's correctly-rounded round()")
	}
}
