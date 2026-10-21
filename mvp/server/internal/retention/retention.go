// Package retention holds the log retention settings of a tenant (issue #298):
// how many days each data class stays online before the archival job
// (internal/archive) seals it into an archive segment and removes it from the
// online store.
//
// The defaults and the floors are here. A floor is the shortest time a class
// may be kept online: a compliance minimum that no setting can undercut. The
// change request that sets a retention (internal/admin, type retention.update)
// refuses anything below it, so the floor is enforced on the server and the
// API; the UI only mirrors it.
package retention

import (
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Class describes one data class with a retention setting.
type Class struct {
	Name  string `json:"class"`
	Label string `json:"label"`
	// Default is the retention when the tenant has set none.
	Default int `json:"default_days"`
	// Min is the floor and Max the ceiling, in days.
	Min int `json:"min_days"`
	Max int `json:"max_days"`
	// Basis says what the age of a record is counted from.
	Basis string `json:"basis"`
}

// MaxDays is the ceiling of every class: ten years.
const MaxDays = 3650

// Classes are the data classes in the order the archival job runs them. The
// audit floor is one year (SOC 2 and ISO 27001 evidence periods are a year);
// campaigns and requests are the evidence of access decisions, so they have the
// same floor; job runs and the notification outbox are operational records.
var Classes = []Class{
	{Name: store.ClassAudit, Label: "Audit events", Default: 730, Min: 365, Max: MaxDays, Basis: "the time of the event"},
	{Name: store.ClassCampaigns, Label: "Closed review campaigns", Default: 730, Min: 365, Max: MaxDays, Basis: "the time the campaign was created (only completed campaigns)"},
	{Name: store.ClassRequests, Label: "Closed and expired requests", Default: 730, Min: 365, Max: MaxDays, Basis: "the time the request was closed (denied, cancelled, expired or removed)"},
	{Name: store.ClassJobRuns, Label: "Job runs", Default: 90, Min: 30, Max: MaxDays, Basis: "the time the run started (finished runs only)"},
	{Name: store.ClassOutbox, Label: "Notification outbox", Default: 90, Min: 30, Max: MaxDays, Basis: "the time the notification was created (delivered, skipped or dead only)"},
}

// Lookup returns the class named name.
func Lookup(name string) (Class, bool) {
	for _, c := range Classes {
		if c.Name == name {
			return c, true
		}
	}
	return Class{}, false
}

// Check refuses a retention below the floor or above the ceiling of its class.
func Check(class string, days int) error {
	c, ok := Lookup(class)
	switch {
	case !ok:
		return fmt.Errorf("unknown class %q", class)
	case days < c.Min:
		return fmt.Errorf("%s: %d days is below the minimum of %d days", c.Label, days, c.Min)
	case days > c.Max:
		return fmt.Errorf("%s: %d days is above the maximum of %d days", c.Label, days, c.Max)
	}
	return nil
}

// Setting is the effective retention of a class.
type Setting struct {
	Class
	Days int `json:"days"`
	// Custom is true when the tenant set it (false: the default applies).
	Custom    bool       `json:"custom"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy *string    `json:"updated_by,omitempty"`
}

// Effective returns the retention of every class for tx's tenant. A stored
// value below the floor (a floor raised later) is lifted to it.
func Effective(tx *store.TenantTx) ([]Setting, error) {
	ps, err := tx.RetentionPolicies()
	if err != nil {
		return nil, err
	}
	byClass := map[string]*store.RetentionPolicy{}
	for _, p := range ps {
		byClass[p.Class] = p
	}
	out := make([]Setting, 0, len(Classes))
	for _, c := range Classes {
		s := Setting{Class: c, Days: c.Default}
		if p := byClass[c.Name]; p != nil {
			s.Days, s.Custom = min(max(p.Days, c.Min), c.Max), true
			at := p.UpdatedAt
			s.UpdatedAt, s.UpdatedBy = &at, p.UpdatedBy
		}
		out = append(out, s)
	}
	return out, nil
}

// Days returns the effective days of one class.
func Days(tx *store.TenantTx, class string) (int, error) {
	ss, err := Effective(tx)
	if err != nil {
		return 0, err
	}
	for _, s := range ss {
		if s.Name == class {
			return s.Days, nil
		}
	}
	return 0, fmt.Errorf("unknown class %q", class)
}

// Cutoff is the time before which a record of a class is past its retention.
func Cutoff(now time.Time, days int) time.Time { return now.AddDate(0, 0, -days) }
