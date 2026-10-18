package abac

import (
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Person is one identity in a simulation result.
type Person struct {
	ID         int64
	Name       string
	Type       string
	Status     string
	Department string
	Title      string
}

// SimResult is what saving a draft condition would change: who matches it,
// and against the saved version, who gains and who loses.
type SimResult struct {
	Evaluated  int      // identities evaluated
	Matching   int      // match the draft
	Before     int      // match the saved version (0 with no saved version)
	Gains      []Person // match the draft, not the saved version (at most MaxListed)
	Loses      []Person // matched the saved version, not the draft (at most MaxListed)
	GainCount  int
	LoseCount  int
	NoAttrs    int // identities for which the draft was unknown: an attribute it tests is missing (denied)
	Unchanged  int
	Truncated  bool
	CurrentVer int // the saved version compared against (0: none)
}

// Simulate evaluates the draft condition for every identity of the tenant and
// compares it with the saved condition (current, nil for a new policy).
// extra holds resource.* and context.* attributes shared by every evaluation
// (context.time and context.hour default to now). Nothing is written.
func Simulate(tx *store.TenantTx, draft *Node, current *store.AbacPolicy, extra Attrs, now time.Time) (*SimResult, error) {
	if err := draft.Validate(); err != nil {
		return nil, err
	}
	var cur *Node
	res := &SimResult{Gains: []Person{}, Loses: []Person{}}
	if current != nil {
		var err error
		if cur, err = Condition(current); err != nil {
			return nil, err
		}
		res.CurrentVer = current.Version
	}
	people, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	base := Merge(ContextAttrs(now, 0), extra)
	for _, p := range people {
		attrs := Merge(IdentityAttrs(p, now), base)
		res.Evaluated++
		nd := draft.Tri(attrs)
		after := nd == True
		before := cur != nil && cur.Tri(attrs) == True
		if nd == Unknown {
			res.NoAttrs++
		}
		if after {
			res.Matching++
		}
		if before {
			res.Before++
		}
		switch {
		case after && !before:
			res.GainCount++
			if len(res.Gains) < MaxListed {
				res.Gains = append(res.Gains, person(p))
			} else {
				res.Truncated = true
			}
		case before && !after:
			res.LoseCount++
			if len(res.Loses) < MaxListed {
				res.Loses = append(res.Loses, person(p))
			} else {
				res.Truncated = true
			}
		default:
			res.Unchanged++
		}
	}
	sort.Slice(res.Gains, func(i, j int) bool { return res.Gains[i].Name < res.Gains[j].Name })
	sort.Slice(res.Loses, func(i, j int) bool { return res.Loses[i].Name < res.Loses[j].Name })
	return res, nil
}

func person(i *store.Identity) Person {
	p := Person{ID: i.ID, Name: i.Name, Type: i.Type, Status: i.Status}
	if i.Department != nil {
		p.Department = *i.Department
	}
	if i.Title != nil {
		p.Title = *i.Title
	}
	return p
}
