package main

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

func TestRateLimitsFollowTheConfiguredBursts(t *testing.T) {
	got := rateLimits(&config.Config{AuthRateBurst: 5000, AnonRateBurst: 4000})
	if got.Auth.Burst != 5000 || got.Anonymous.Burst != 4000 {
		t.Errorf("rate limits = %+v", got)
	}
	// the defaults of the configuration are the limiter's own defaults
	d := rateLimits(&config.Config{AuthRateBurst: 30, AnonRateBurst: 120})
	if d.Auth.Burst != 30 || d.Anonymous.Burst != 120 {
		t.Errorf("default bursts = %+v", d)
	}
}
