package helpdesk

import (
	"testing"
	"time"
)

func TestDetect(t *testing.T) {
	reset := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	h := func(n int) time.Time { return reset.Add(time.Duration(n) * time.Hour) }
	dev := func(at time.Time) Signal { return Signal{Kind: SignalMFADevice, Device: "Pixel 9", At: at} }
	in := func(loc string, at time.Time) Signal { return Signal{Kind: SignalSignIn, Location: loc, At: at} }
	tests := []struct {
		name string
		sigs []Signal
		hit  bool
	}{
		{"new device and new location within 24h", []Signal{in("Oslo", h(-48)), dev(h(2)), in("Lagos", h(3))}, true},
		{"location case and spacing are normalised", []Signal{in(" oslo ", h(-48)), dev(h(2)), in("OSLO", h(3))}, false},
		{"new device but a known location", []Signal{in("Oslo", h(-48)), dev(h(2)), in("Oslo", h(3))}, false},
		{"new location but no new device", []Signal{in("Oslo", h(-48)), in("Lagos", h(3))}, false},
		{"new device but no sign-in", []Signal{in("Oslo", h(-48)), dev(h(2))}, false},
		{"both after the 24h window", []Signal{in("Oslo", h(-48)), dev(h(25)), in("Lagos", h(26))}, false},
		{"device inside the window, sign-in outside", []Signal{in("Oslo", h(-48)), dev(h(2)), in("Lagos", h(30))}, false},
		{"exactly at 24h is inside", []Signal{dev(h(24)), in("Lagos", h(24))}, true},
		{"signals before the reset do not count", []Signal{in("Oslo", h(-48)), dev(h(-2)), in("Lagos", h(-1))}, false},
		{"no history: the first sign-in location is new", []Signal{dev(h(1)), in("Lagos", h(2))}, true},
		{"a sign-in without a location is ignored", []Signal{dev(h(1)), in("", h(2))}, false},
		{"order of signals does not matter", []Signal{in("Lagos", h(3)), dev(h(2)), in("Oslo", h(-48))}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(reset, tt.sigs)
			if (got != nil) != tt.hit {
				t.Fatalf("Detect = %+v, want hit=%v", got, tt.hit)
			}
			if got != nil && (got.Rule != RuleResetTakeover || got.Location == "" || got.Device == "") {
				t.Errorf("hit is incomplete: %+v", got)
			}
		})
	}
}
