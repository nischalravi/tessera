package worker

import (
	"errors"
	"testing"
)

func TestCheckSyncSchedule(t *testing.T) {
	for _, tc := range []struct {
		delta, full int
		ok          bool
	}{
		{0, 0, true}, {5, 0, true}, {15, 24, true}, {1440, 720, true},
		{4, 0, false}, {1441, 0, false}, {-5, 0, false}, {0, 721, false}, {0, -1, false},
	} {
		err := CheckSyncSchedule(tc.delta, tc.full)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrScheduleBounds)) {
			t.Errorf("CheckSyncSchedule(%d, %d) = %v, want ok=%t", tc.delta, tc.full, err, tc.ok)
		}
	}
}
