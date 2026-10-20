package queue_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/queue"
)

func TestParseSpecAndNext(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse("2006-01-02 15:04:05", s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	tests := []struct {
		spec, from, want string
	}{
		{"@every 30s", "2026-01-01 10:00:07", "2026-01-01 10:00:37"},
		{"* * * * *", "2026-01-01 10:00:07", "2026-01-01 10:01:00"},
		{"*/15 * * * *", "2026-01-01 10:15:00", "2026-01-01 10:30:00"},
		{"30 2 * * *", "2026-01-01 10:00:00", "2026-01-02 02:30:00"},
		{"0 9 * * 1-5", "2026-01-02 10:00:00", "2026-01-05 09:00:00"},    // Friday evening -> Monday
		{"0 0 1 * *", "2026-01-31 12:00:00", "2026-02-01 00:00:00"},      // first of the month
		{"0 0 29 2 *", "2026-01-01 00:00:00", "2028-02-29 00:00:00"},     // leap day
		{"5,35 8-9 * * *", "2026-01-01 08:36:00", "2026-01-01 09:05:00"}, // lists and ranges
		{"0 0 13 * 5", "2026-01-01 00:00:00", "2026-01-02 00:00:00"},     // dom or dow when both are set
		{"0 12 * * 7", "2026-01-01 00:00:00", "2026-01-04 12:00:00"},     // 7 is Sunday
		{"10-40/10 * * * *", "2026-01-01 00:00:00", "2026-01-01 00:10:00"},
	}
	for _, tc := range tests {
		sp, err := queue.ParseSpec(tc.spec)
		if err != nil {
			t.Errorf("%q: %v", tc.spec, err)
			continue
		}
		if got := sp.Next(at(tc.from)); !got.Equal(at(tc.want)) {
			t.Errorf("%q after %s = %s, want %s", tc.spec, tc.from, got.Format(time.DateTime), tc.want)
		}
	}
	for _, bad := range []string{"", "@every", "@every 0s", "@every soon", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *",
		"* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *", "* * * * * *"} {
		if _, err := queue.ParseSpec(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestBackoffDelay(t *testing.T) {
	mk := func(r float64) queue.Backoff {
		return queue.Backoff{Base: 10 * time.Second, Max: time.Minute, Jitter: 0.2, Rand: func() float64 { return r }}
	}
	tests := []struct {
		attempts int
		r        float64
		want     time.Duration
	}{
		{1, 0.5, 10 * time.Second}, {2, 0.5, 20 * time.Second}, {3, 0.5, 40 * time.Second},
		{4, 0.5, time.Minute}, {9, 0.5, time.Minute}, // capped
		{0, 0.5, 10 * time.Second}, // treated as the first
		{1, 0, 8 * time.Second}, {1, 0.999999, 12*time.Second - 12*time.Microsecond},
	}
	for _, tc := range tests {
		got := mk(tc.r).Delay(tc.attempts)
		if d := got - tc.want; d < -time.Millisecond || d > time.Millisecond {
			t.Errorf("Delay(%d) with rand %v = %v, want %v", tc.attempts, tc.r, got, tc.want)
		}
	}
	// the real jitter stays inside plus or minus 20% of the unjittered wait
	b := queue.Backoff{Base: time.Minute, Max: time.Hour, Jitter: 0.2}
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		d := b.Delay(2)
		if d < 96*time.Second || d > 144*time.Second {
			t.Fatalf("jittered delay %v out of range", d)
		}
		seen[d] = true
	}
	if len(seen) < 10 {
		t.Error("no jitter")
	}
}
