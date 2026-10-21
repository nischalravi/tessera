// Package prefs holds a signed-in user's preferences (issue #298): time zone,
// date format, locale and the page to land on after sign-in. They are stored per
// user, changed only by that user, and used by the UI to render dates and to
// redirect from the root. An empty value means "the default": the browser's time
// zone and locale, ISO dates, the home page.
package prefs

import (
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Date formats. The UI renders each with the user's time zone.
const (
	DateISO  = "iso"  // 2026-10-21
	DateDMY  = "dmy"  // 21/10/2026
	DateMDY  = "mdy"  // 10/21/2026
	DateLong = "long" // 21 Oct 2026
)

// DateFormats are the formats a user may choose.
var DateFormats = []string{DateISO, DateDMY, DateMDY, DateLong}

// Locales are the locales a user may choose (BCP 47 tags the UI's formatting understands).
var Locales = []string{"en-US", "en-GB", "en-CA", "en-AU", "de-DE", "fr-FR", "es-ES", "pt-BR", "ja-JP"}

// LandingPages are the pages a user may land on after signing in: UI paths,
// never an external address, so the setting cannot be an open redirect.
var LandingPages = []string{"/", "/inbox", "/access/request", "/access/mine", "/access/requests", "/governance/reviews",
	"/insights/risk", "/insights/sod", "/directory/people", "/alerts"}

// MaxTimeZone caps a time zone name.
const MaxTimeZone = 64

// Preferences are one user's choices.
type Preferences struct {
	TimeZone    string `json:"time_zone"`
	DateFormat  string `json:"date_format"`
	Locale      string `json:"locale"`
	LandingPage string `json:"landing_page"`
}

// Check validates preferences from the API and returns them in canonical form.
func (p Preferences) Check() (Preferences, error) {
	p.TimeZone = strings.TrimSpace(p.TimeZone)
	switch {
	case len(p.TimeZone) > MaxTimeZone || (p.TimeZone != "" && !validZone(p.TimeZone)):
		return Preferences{}, cfgerr.Refuse(422, "invalid_time_zone", "the time zone is an IANA name such as Europe/Berlin or America/New_York")
	case p.DateFormat != "" && !slices.Contains(DateFormats, p.DateFormat):
		return Preferences{}, cfgerr.Refuse(422, "invalid_date_format", "the date format is one of %v", DateFormats)
	case p.Locale != "" && !slices.Contains(Locales, p.Locale):
		return Preferences{}, cfgerr.Refuse(422, "invalid_locale", "the locale is one of %v", Locales)
	case p.LandingPage != "" && !slices.Contains(LandingPages, p.LandingPage):
		return Preferences{}, cfgerr.Refuse(422, "invalid_landing_page", "the landing page is one of %v", LandingPages)
	}
	return p, nil
}

// validZone accepts an IANA zone name the server's tz database knows. "Local"
// is refused: it means the server's own zone, which is no use to a person
// elsewhere. Names with a path in them are refused before the lookup.
func validZone(name string) bool {
	if strings.EqualFold(name, "local") || strings.ContainsAny(name, " \t\n\\") || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
		return false
	}
	_, err := time.LoadLocation(name)
	return err == nil
}

// Load returns the user's preferences (the zero value, all defaults, for a user who never saved any).
func Load(tx *store.TenantTx, user uuid.UUID) (Preferences, error) {
	row, err := tx.UserPreferences(user)
	if store.ErrNoSettings(err) {
		return Preferences{}, nil
	} else if err != nil {
		return Preferences{}, err
	}
	return Preferences{TimeZone: row.TimeZone, DateFormat: row.DateFormat, Locale: row.Locale, LandingPage: row.LandingPage}, nil
}

func detail(p Preferences) ojson.Object {
	return ojson.Object{{Key: "time_zone", Value: p.TimeZone}, {Key: "date_format", Value: p.DateFormat},
		{Key: "locale", Value: p.Locale}, {Key: "landing_page", Value: p.LandingPage}}
}

// Save replaces the user's preferences and audits the change in the same transaction.
func Save(tx *store.TenantTx, user uuid.UUID, display string, p Preferences, now time.Time) (Preferences, error) {
	p, err := p.Check()
	if err != nil {
		return Preferences{}, err
	}
	old, err := Load(tx, user)
	if err != nil {
		return Preferences{}, err
	}
	if err := tx.PutUserPreferences(user, &store.UserPreferencesRow{TimeZone: p.TimeZone, DateFormat: p.DateFormat,
		Locale: p.Locale, LandingPage: p.LandingPage}, now); err != nil {
		return Preferences{}, err
	}
	d := append(detail(p), ojson.KV{Key: "previous", Value: detail(old)})
	return p, tx.Audit(now, display, "user.preferences.update", d)
}
