package prefs

import (
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
)

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    Preferences
		code string
	}{
		{"all defaults", Preferences{}, ""},
		{"all set", Preferences{TimeZone: "Europe/Berlin", DateFormat: DateDMY, Locale: "de-DE", LandingPage: "/inbox"}, ""},
		{"utc", Preferences{TimeZone: "UTC"}, ""},
		{"padded zone is trimmed", Preferences{TimeZone: " Asia/Tokyo "}, ""},
		{"unknown zone", Preferences{TimeZone: "Mars/Olympus"}, "invalid_time_zone"},
		{"the server's own zone", Preferences{TimeZone: "Local"}, "invalid_time_zone"},
		{"path traversal", Preferences{TimeZone: "../zoneinfo/UTC"}, "invalid_time_zone"},
		{"absolute path", Preferences{TimeZone: "/etc/localtime"}, "invalid_time_zone"},
		{"long zone", Preferences{TimeZone: string(make([]byte, 100))}, "invalid_time_zone"},
		{"unknown date format", Preferences{DateFormat: "yy"}, "invalid_date_format"},
		{"unknown locale", Preferences{Locale: "tlh"}, "invalid_locale"},
		{"external landing page", Preferences{LandingPage: "https://evil.example/"}, "invalid_landing_page"},
		{"protocol-relative landing page", Preferences{LandingPage: "//evil.example"}, "invalid_landing_page"},
		{"a page outside the list", Preferences{LandingPage: "/admin/users"}, "invalid_landing_page"},
	} {
		got, err := tc.p.Check()
		var ce *cfgerr.Error
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.code != "" && (!errors.As(err, &ce) || ce.Code != tc.code || ce.Status != 422):
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		case tc.name == "padded zone is trimmed" && got.TimeZone != "Asia/Tokyo":
			t.Errorf("zone = %q", got.TimeZone)
		}
	}
	for _, p := range LandingPages {
		if p[0] != '/' || (len(p) > 1 && p[1] == '/') {
			t.Errorf("landing page %q is not a local path", p)
		}
	}
}
