package helpdesk

import (
	"strings"
	"time"
)

// Detection: account takeover after a help-desk reset. A reset hands the
// account to whoever passed the verification, so an attacker who talked their
// way through leaves two traces within a day: a new MFA device and a sign-in
// from somewhere the account has not signed in before.

// RuleResetTakeover is the detection's rule id.
const RuleResetTakeover = "helpdesk.post_reset_takeover"

// Window is how long after a reset the detection watches.
const Window = 24 * time.Hour

// Signal kinds.
const (
	SignalMFADevice = "mfa_device_added"
	SignalSignIn    = "sign_in"
)

// Signal is one observation about an identity.
type Signal struct {
	Kind     string
	Location string
	Device   string
	At       time.Time
}

// Hit is a detection result.
type Hit struct {
	Rule        string    `json:"rule"`
	ResetAt     time.Time `json:"reset_at"`
	Device      string    `json:"device"`
	DeviceAt    time.Time `json:"device_added_at"`
	Location    string    `json:"location"`
	SignInAt    time.Time `json:"sign_in_at"`
	KnownBefore []string  `json:"known_locations"`
}

func normLoc(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Detect reports a hit when, within Window after resetAt, the identity gained
// a new MFA device and signed in from a location it had not signed in from
// before the reset. Both signals are required. A location counts as known when
// a sign-in from it happened at or before the reset; an identity with no
// sign-in history has no known locations, so its first sign-in is new. Detect
// is pure.
func Detect(resetAt time.Time, signals []Signal) *Hit {
	end := resetAt.Add(Window)
	known := map[string]bool{}
	knownList := []string{}
	for _, s := range signals {
		if s.Kind == SignalSignIn && !s.At.After(resetAt) {
			if l := normLoc(s.Location); l != "" && !known[l] {
				known[l] = true
				knownList = append(knownList, l)
			}
		}
	}
	inWindow := func(t time.Time) bool { return t.After(resetAt) && !t.After(end) }
	var dev, login *Signal
	for i := range signals {
		s := &signals[i]
		if !inWindow(s.At) {
			continue
		}
		switch {
		case s.Kind == SignalMFADevice && dev == nil:
			dev = s
		case s.Kind == SignalSignIn && login == nil && normLoc(s.Location) != "" && !known[normLoc(s.Location)]:
			login = s
		}
	}
	if dev == nil || login == nil {
		return nil
	}
	return &Hit{Rule: RuleResetTakeover, ResetAt: resetAt, Device: dev.Device, DeviceAt: dev.At,
		Location: login.Location, SignInAt: login.At, KnownBefore: knownList}
}
