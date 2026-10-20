package api

import "testing"

func TestBoundedLimit(t *testing.T) {
	tests := []struct {
		v    int64
		want int
	}{
		{1, 1}, {200, 200}, {500, 500}, {0, 200}, {-1, 200}, {501, 200},
		{1 << 40, 200}, {-(1 << 40), 200}, {9223372036854775807, 200}, {-9223372036854775808, 200},
	}
	for _, tc := range tests {
		if got := boundedLimit(tc.v, 200, 500); got != tc.want {
			t.Errorf("boundedLimit(%d) = %d, want %d", tc.v, got, tc.want)
		}
	}
}
