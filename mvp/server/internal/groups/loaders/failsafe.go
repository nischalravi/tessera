package loaders

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Failsafe is a loader's guard against a bad source (G-59, design §9.1). A run
// that breaks a limit is held. Unset fields have the defaults below; the
// stored form always has them filled, so what a loader enforces is visible.
//
//	max_removed_percent         members removed from one group, of its loader members [20]
//	max_removed                 members removed from one group [500]
//	min_group_size              a group the source returns smaller than this [unset]
//	max_groups_emptied_percent  groups emptied or deleted in one run, of the loader's groups [5]
//	max_unresolved_percent      subjects of the source that match no identity [2]
type Failsafe struct {
	MaxRemovedPercent       *float64 `json:"max_removed_percent,omitempty"`
	MaxRemoved              *int     `json:"max_removed,omitempty"`
	MinGroupSize            *int     `json:"min_group_size,omitempty"`
	MaxGroupsEmptiedPercent *float64 `json:"max_groups_emptied_percent,omitempty"`
	MaxUnresolvedPercent    *float64 `json:"max_unresolved_percent,omitempty"`
}

// Defaults of the failsafe.
const (
	DefaultMaxRemovedPercent       = 20.0
	DefaultMaxRemoved              = 500
	DefaultMaxGroupsEmptiedPercent = 5.0
	DefaultMaxUnresolvedPercent    = 2.0
)

// Normalize fills the defaults and checks the limits.
func (f Failsafe) Normalize() (Failsafe, error) {
	pct := func(name string, p **float64, def float64) error {
		if *p == nil {
			v := def
			*p = &v
		}
		if **p < 0 || **p > 100 {
			return invalid("invalid_failsafe", "%s is 0 to 100", name)
		}
		return nil
	}
	if err := pct("max_removed_percent", &f.MaxRemovedPercent, DefaultMaxRemovedPercent); err != nil {
		return f, err
	}
	if err := pct("max_groups_emptied_percent", &f.MaxGroupsEmptiedPercent, DefaultMaxGroupsEmptiedPercent); err != nil {
		return f, err
	}
	if err := pct("max_unresolved_percent", &f.MaxUnresolvedPercent, DefaultMaxUnresolvedPercent); err != nil {
		return f, err
	}
	if f.MaxRemoved == nil {
		v := DefaultMaxRemoved
		f.MaxRemoved = &v
	}
	if *f.MaxRemoved < 0 {
		return f, invalid("invalid_failsafe", "max_removed is 0 or more")
	}
	if f.MinGroupSize != nil && *f.MinGroupSize < 0 {
		return f, invalid("invalid_failsafe", "min_group_size is 0 or more")
	}
	return f, nil
}

// ParseFailsafe reads a stored failsafe (already normalized).
func ParseFailsafe(raw string) (Failsafe, error) {
	var f Failsafe
	if raw != "" {
		if err := strictDecode(json.RawMessage(raw), &f); err != nil {
			return f, fmt.Errorf("loaders: stored failsafe: %w", err)
		}
	}
	return f.Normalize()
}

// Trip is one limit a run broke.
type Trip struct {
	Rule  string  `json:"rule"`
	Group string  `json:"group,omitempty"`
	Value float64 `json:"value"`
	Limit float64 `json:"limit"`
	// Detail says it in words.
	Detail string `json:"detail"`
}

// Counts are what Evaluate needs besides the plan.
type Counts struct {
	// LoaderGroups is the number of live groups the loader owns before the run.
	LoaderGroups int
	// SourceRefs is the number of (group, subject) references the source made.
	SourceRefs int
	// UnresolvedRefs is how many of them matched no identity.
	UnresolvedRefs int
}

// Evaluate returns the limits the plan breaks, in a stable order (none: the
// run may apply).
func (f Failsafe) Evaluate(p *Plan, c Counts) []Trip {
	var trips []Trip
	for i := range p.Groups {
		g := &p.Groups[i]
		removed := len(g.Remove)
		if g.Current > 0 && removed > 0 {
			if pct := 100 * float64(removed) / float64(g.Current); pct > *f.MaxRemovedPercent {
				trips = append(trips, Trip{Rule: "max_removed_percent", Group: g.Name, Value: pct, Limit: *f.MaxRemovedPercent,
					Detail: fmt.Sprintf("%s: %d of %d members would be removed (%.1f%%, limit %.1f%%)", g.Name, removed, g.Current, pct, *f.MaxRemovedPercent)})
			}
		}
		if removed > *f.MaxRemoved {
			trips = append(trips, Trip{Rule: "max_removed", Group: g.Name, Value: float64(removed), Limit: float64(*f.MaxRemoved),
				Detail: fmt.Sprintf("%s: %d members would be removed (limit %d)", g.Name, removed, *f.MaxRemoved)})
		}
		if f.MinGroupSize != nil && !g.Missing && g.Size < *f.MinGroupSize {
			trips = append(trips, Trip{Rule: "min_group_size", Group: g.Name, Value: float64(g.Size), Limit: float64(*f.MinGroupSize),
				Detail: fmt.Sprintf("%s: the source returns %d members (minimum %d)", g.Name, g.Size, *f.MinGroupSize)})
		}
	}
	if c.LoaderGroups > 0 {
		emptied := p.EmptiedGroups()
		if pct := 100 * float64(emptied) / float64(c.LoaderGroups); emptied > 0 && pct > *f.MaxGroupsEmptiedPercent {
			trips = append(trips, Trip{Rule: "max_groups_emptied_percent", Value: pct, Limit: *f.MaxGroupsEmptiedPercent,
				Detail: fmt.Sprintf("%d of %d groups would be emptied or deleted (%.1f%%, limit %.1f%%)", emptied, c.LoaderGroups, pct, *f.MaxGroupsEmptiedPercent)})
		}
	}
	if c.SourceRefs > 0 && c.UnresolvedRefs > 0 {
		if pct := 100 * float64(c.UnresolvedRefs) / float64(c.SourceRefs); pct > *f.MaxUnresolvedPercent {
			trips = append(trips, Trip{Rule: "max_unresolved_percent", Value: pct, Limit: *f.MaxUnresolvedPercent,
				Detail: fmt.Sprintf("%d of %d subjects match no identity (%.1f%%, limit %.1f%%)", c.UnresolvedRefs, c.SourceRefs, pct, *f.MaxUnresolvedPercent)})
		}
	}
	sort.SliceStable(trips, func(i, j int) bool {
		if trips[i].Rule != trips[j].Rule {
			return trips[i].Rule < trips[j].Rule
		}
		return trips[i].Group < trips[j].Group
	})
	return trips
}
