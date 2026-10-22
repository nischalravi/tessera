// Package deleteguard is the deletion threshold guard: a safety net so a mistake (a bad admin
// action, a bad source feed, a misconfigured connector or loader) cannot delete everything.
//
// Every deletion path of a guarded category asks Admit before it removes anything. Admit counts
// the deletions already applied in the category's sliding window (a per-tenant ledger), lets
// through only what fits under the threshold, holds the rest as a "held deletion" (which items,
// why, who and where from), audits it and leaves it to a second admin to release or discard.
// The check and the ledger write run in the caller's transaction, after a write to the
// category's counter row, so concurrent requests and workers cannot together exceed the
// threshold (a row lock on Postgres, the single writer on SQLite).
//
// Rules: docs/knowledge is silent on this; the behaviour is in mvp/README.md "Deletion threshold
// guard".
package deleteguard

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Categories of deletion the guard counts.
const (
	CatGroups     = "groups"        // soft delete and purge of groups
	CatFolders    = "folders"       // folders removed (a recursive delete removes a tree)
	CatMembers    = "group_members" // direct memberships removed by any path
	CatAccounts   = "accounts"      // connector-sync account removals and provisioning remove/disable ops
	CatIdentities = "identities"    // identity disable and leaver end
)

// Categories lists them in display order.
var Categories = []string{CatGroups, CatFolders, CatMembers, CatAccounts, CatIdentities}

// Modes of a policy.
const (
	ModeHoldExcess = "hold_excess" // apply up to the threshold, hold the rest (the default)
	ModeHoldAll    = "hold_all"    // hold the whole batch when it would pass the threshold
	ModeOff        = "off"
)

// Bounds and defaults.
const (
	MaxWindowMinutes = 7 * 24 * 60
	// DefaultHoldExpiryHours is how long a hold waits before it expires (as discarded).
	DefaultHoldExpiryHours = 7 * 24
	// MinPercentLimit is the least a percent threshold allows in a window, so that a small tenant's
	// percent of a tiny population cannot block a single deletion (5% of 12 groups is 0).
	MinPercentLimit = 5
)

// Policy is the threshold of one category. MaxCount and MaxPercent (of the population in scope)
// may each be nil; when both are set the lower limit applies.
type Policy struct {
	Category      string     `json:"category"`
	MaxCount      *int       `json:"max_count"`
	MaxPercent    *float64   `json:"max_percent"`
	WindowMinutes int        `json:"window_minutes"`
	Mode          string     `json:"mode"`
	Default       bool       `json:"default"`
	Version       int        `json:"version"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

func intp(v int) *int           { return &v }
func floatp(v float64) *float64 { return &v }

// Defaults are the policies a tenant has until it changes them: on for every category.
func Defaults() map[string]Policy {
	d := func(c string, n *int, pct *float64) Policy {
		return Policy{Category: c, MaxCount: n, MaxPercent: pct, WindowMinutes: 60, Mode: ModeHoldExcess, Default: true}
	}
	return map[string]Policy{
		CatGroups:     d(CatGroups, intp(25), nil),
		CatFolders:    d(CatFolders, intp(10), nil),
		CatMembers:    d(CatMembers, intp(500), floatp(10)),
		CatAccounts:   d(CatAccounts, intp(200), floatp(5)),
		CatIdentities: d(CatIdentities, intp(50), floatp(2)),
	}
}

// ValidCategory says whether c is a category.
func ValidCategory(c string) bool {
	for _, k := range Categories {
		if k == c {
			return true
		}
	}
	return false
}

// Check validates a policy.
func (p Policy) Check() error {
	if !ValidCategory(p.Category) {
		return fmt.Errorf("%q is not a deletion category", p.Category)
	}
	switch p.Mode {
	case ModeHoldExcess, ModeHoldAll, ModeOff:
	default:
		return fmt.Errorf("%s: mode is hold_excess, hold_all or off", p.Category)
	}
	if p.WindowMinutes < 1 || p.WindowMinutes > MaxWindowMinutes {
		return fmt.Errorf("%s: window_minutes is 1 to %d", p.Category, MaxWindowMinutes)
	}
	if p.MaxCount != nil && (*p.MaxCount < 0 || *p.MaxCount > 10_000_000) {
		return fmt.Errorf("%s: max_count is 0 to 10000000", p.Category)
	}
	if p.MaxPercent != nil && (math.IsNaN(*p.MaxPercent) || *p.MaxPercent < 0 || *p.MaxPercent > 100) {
		return fmt.Errorf("%s: max_percent is 0 to 100", p.Category)
	}
	if p.Mode != ModeOff && p.MaxCount == nil && p.MaxPercent == nil {
		return fmt.Errorf("%s: set max_count or max_percent, or turn the category off", p.Category)
	}
	return nil
}

// Window is the policy's window.
func (p Policy) Window() time.Duration { return time.Duration(p.WindowMinutes) * time.Minute }

// Limit is how many deletions the window allows given the population in scope; nil: no limit
// (mode off).
func (p Policy) Limit(population int) *int {
	if p.Mode == ModeOff {
		return nil
	}
	var lim *int
	if p.MaxCount != nil {
		lim = intp(*p.MaxCount)
	}
	if p.MaxPercent != nil {
		v := int(math.Floor(*p.MaxPercent / 100 * float64(population)))
		if v < MinPercentLimit {
			v = MinPercentLimit
		}
		if lim == nil || v < *lim {
			lim = &v
		}
	}
	return lim
}

// rank orders modes from the strictest.
func modeRank(m string) int {
	switch m {
	case ModeHoldAll:
		return 0
	case ModeHoldExcess:
		return 1
	}
	return 2
}

// Loosens reports whether next is a weaker safety setting than cur for a tenant whose population
// in scope is pop: a weaker mode, or a higher limit per minute of window (the limit is the lower
// of the count and the percent of pop, see Limit). Loosening takes two admins.
func Loosens(cur, next Policy, pop int) bool {
	if modeRank(next.Mode) > modeRank(cur.Mode) {
		return true
	}
	if next.Mode == ModeOff {
		return false
	}
	nl, cl := next.Limit(pop), cur.Limit(pop)
	if cl == nil || nl == nil {
		return cl != nil // a limit was removed
	}
	return float64(*nl)/float64(next.WindowMinutes) > float64(*cl)/float64(cur.WindowMinutes)
}

func fromRow(r *store.DeletionPolicy) Policy {
	at := r.UpdatedAt
	return Policy{Category: r.Category, MaxCount: r.MaxCount, MaxPercent: r.MaxPercent, WindowMinutes: r.WindowMinutes,
		Mode: r.Mode, Version: r.Version, UpdatedAt: &at}
}

// Effective returns every category's policy in display order: the stored one, or the default.
func Effective(tx *store.TenantTx) ([]Policy, error) {
	rows, err := tx.DeletionPolicies()
	if err != nil {
		return nil, err
	}
	have := map[string]Policy{}
	for _, r := range rows {
		have[r.Category] = fromRow(r)
	}
	def := Defaults()
	out := make([]Policy, 0, len(Categories))
	for _, c := range Categories {
		if p, ok := have[c]; ok {
			out = append(out, p)
		} else {
			out = append(out, def[c])
		}
	}
	return out, nil
}

// PolicyOf returns one category's effective policy.
func PolicyOf(tx *store.TenantTx, category string) (Policy, error) {
	ps, err := Effective(tx)
	if err != nil {
		return Policy{}, err
	}
	for _, p := range ps {
		if p.Category == category {
			return p, nil
		}
	}
	return Policy{}, fmt.Errorf("deleteguard: %q is not a category", category)
}

// Set stores a policy (the admin change that applies it has checked who may).
func Set(tx *store.TenantTx, p Policy, by *string, now time.Time) error {
	if err := p.Check(); err != nil {
		return err
	}
	return tx.PutDeletionPolicy(&store.DeletionPolicy{Category: p.Category, MaxCount: p.MaxCount, MaxPercent: p.MaxPercent,
		WindowMinutes: p.WindowMinutes, Mode: p.Mode, UpdatedBy: by}, now)
}

// HoldExpiryHours is how long a hold waits before it expires.
func HoldExpiryHours(tx *store.TenantTx) (int, error) {
	s, err := tx.DeletionSettingsRow()
	if err == store.ErrNotFound {
		return DefaultHoldExpiryHours, nil
	}
	if err != nil {
		return 0, err
	}
	return s.HoldExpiryHours, nil
}

// Usage is a category's policy with how much of its window is used.
type Usage struct {
	Policy
	Used       int  `json:"used"`
	Population int  `json:"population"`
	Limit      *int `json:"limit"`
	Remaining  *int `json:"remaining"`
}

// UsageOf reports every category's window usage at now.
func UsageOf(tx *store.TenantTx, now time.Time) ([]Usage, error) {
	ps, err := Effective(tx)
	if err != nil {
		return nil, err
	}
	out := make([]Usage, 0, len(ps))
	for _, p := range ps {
		pop, err := tx.DeletionPopulation(p.Category)
		if err != nil {
			return nil, err
		}
		used, err := tx.DeletionsApplied(p.Category, now.Add(-p.Window()))
		if err != nil {
			return nil, err
		}
		u := Usage{Policy: p, Used: used, Population: pop, Limit: p.Limit(pop)}
		if u.Limit != nil {
			r := max(*u.Limit-used, 0)
			u.Remaining = &r
		}
		out = append(out, u)
	}
	return out, nil
}

// sortItems puts items in the deterministic order Admit applies them in.
func sortItems(items []Item) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Ref < items[j].Ref
	})
}
