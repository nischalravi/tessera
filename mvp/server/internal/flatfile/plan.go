package flatfile

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Plan is the dry run of one file: what Apply would add, change and remove, and every row it would refuse.
// Nothing is written. The guard figures are an estimate: the deletion guard decides when the file is applied
// (its window counts earlier removals too).
type Plan struct {
	System    string
	Kind      string
	RowsTotal int
	Errors    []RowError
	Changes   []Change
	Added     int
	Changed   int
	Removed   int
	Unchanged int
	Guard     *GuardPreview
	// Claims (a people import) are the people whose email matches existing connector accounts nobody owns yet:
	// the next sync correlates those accounts to the person, who then holds their access.
	Claims []Claim
}

// Claim is one imported person and the uncorrelated accounts in other systems the next sync would correlate to them.
type Claim struct {
	Key      string   `json:"key"` // external id of the person
	Email    string   `json:"email"`
	Accounts int      `json:"accounts"`
	Systems  []string `json:"systems"`
}

// GuardPreview is how the deletion guard would see the removals of a plan.
type GuardPreview struct {
	Category  string   `json:"category"`
	Mode      string   `json:"mode"`
	Limit     *int     `json:"limit"` // nil: no limit
	Active    int      `json:"active"`
	Removals  int      `json:"removals"`
	WouldHold bool     `json:"would_hold"`
	Reasons   []string `json:"reasons,omitempty"`
}

// MakePlan reads and compares a file as Apply would, in the caller's transaction, and changes nothing.
func MakePlan(c *store.TenantTx, now time.Time, in Input) (*Plan, error) {
	p, err := prepare(c, now, in)
	if err != nil {
		return nil, err
	}
	pl := &Plan{System: in.System, Kind: in.Kind, RowsTotal: p.up.RowsTotal, Errors: p.errs}
	if len(p.errs) > 0 {
		return pl, nil
	}
	pl.Changes = p.changes
	pl.Added, pl.Changed, pl.Removed, pl.Unchanged = len(p.delta.Added), len(p.delta.Changed), len(p.delta.Removed), p.delta.Unchanged
	if in.Kind == KindAccounts && pl.Removed > 0 {
		if pl.Guard, err = guardPreview(c, in.System, p); err != nil {
			return nil, err
		}
	}
	return pl, nil
}

func guardPreview(c *store.TenantTx, system string, p *prepared) (*GuardPreview, error) {
	all, err := c.Accounts()
	if err != nil {
		return nil, err
	}
	active, gone := 0, 0
	byXID := map[string]bool{}
	for _, a := range all {
		if a.System == system && a.Status == "active" {
			active++
			byXID[a.ExternalID] = true
		}
	}
	for _, r := range p.delta.Removed {
		if byXID[r.Key] {
			gone++
		}
	}
	return previewGuard(c, deleteguard.CatAccounts, gone, active, deleteguard.FeedChecks(active, len(p.accounts), ""))
}

// previewGuard is how the guard would treat removals of a source-driven feed: its mode (the default for a
// feed is hold_all), the limit of the window, and the feed checks that hold the whole batch.
func previewGuard(c *store.TenantTx, category string, removals, population int, sanity []string) (*GuardPreview, error) {
	tp, err := deleteguard.PolicyOf(c, category)
	if err != nil {
		return nil, err
	}
	pol := deleteguard.Resolve(tp, nil, true).Policy
	g := &GuardPreview{Category: category, Mode: pol.Mode, Limit: pol.Limit(population), Active: population, Removals: removals, Reasons: sanity}
	g.WouldHold = removals > 0 && pol.Mode != deleteguard.ModeOff &&
		(len(sanity) > 0 || (g.Limit != nil && removals > *g.Limit))
	return g, nil
}
