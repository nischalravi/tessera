package model

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Simulation (issue #48, GR-5; design §10.11 POST /api/groups:simulate). A
// simulation answers "what would these changes do to memberships?" by running
// the real operations, the real engine included, and then undoing all of it:
// everything runs between a savepoint and a rollback to it, so nothing it wrote
// (rows, change events, audit events, the engine's queue and counters) survives.
// The effective changes are read back from the events the engine wrote before
// the rollback. The request is audited by the API's http.request event only.

// Simulation limits.
const (
	// MaxSimChanges bounds the changes of one simulation.
	MaxSimChanges = 100
	// SimBudget is the engine's synchronous budget during a simulation. A change
	// that would need more is refused rather than queued (nothing may be queued).
	SimBudget = 100_000
	// MaxSimEvents bounds the effective events one simulation reads back.
	MaxSimEvents = 100_000
	// SimSample is how many identities a group's diff lists by name.
	SimSample = 100
)

// Simulated change kinds.
const (
	ChangeAddMember          = "add_member"
	ChangeRemoveMember       = "remove_member"
	ChangeSetComposite       = "set_composite"
	ChangeConvertToComposite = "convert_to_composite"
)

// Change is one change to simulate.
type Change struct {
	Kind  string
	Group store.GroupID
	// add_member: an identity (Identity) or a nested group (Member).
	Identity    *int64
	Member      store.GroupID
	EnabledFrom *time.Time
	DisabledAt  *time.Time
	Reason      string
	// remove_member: an identity id (digits) or a group id (UUID).
	Remove string
	// set_composite and convert_to_composite.
	Op             store.CompositeOp
	Factors        []store.GroupID
	DiscardMembers bool
}

// SimChange is what one change would do to the group it names.
type SimChange struct {
	Index int
	Kind  string
	Group store.GroupID
	Name  string
	// Status is created, updated or removed for a member change, definition for a composite.
	Status string
}

// SimMember is an identity of a diff.
type SimMember struct {
	Identity int64
	Name     string
}

// SimGroup is one group whose effective members would change: those of the
// groups the changes name (Targeted), and those of every group that contains
// them through nesting or a composite (downstream).
type SimGroup struct {
	Group    store.GroupID
	Name     string
	Targeted bool
	Before   int64
	After    int64
	Added    int
	Removed  int
	// AddedSample and RemovedSample list the first SimSample identities (by id) of each side.
	AddedSample   []SimMember
	RemovedSample []SimMember
}

// SimResult is the diff of a simulation.
type SimResult struct {
	Changes []SimChange
	Groups  []SimGroup
	Added   int // effective memberships gained, over all groups
	Removed int // effective memberships lost, over all groups
	// Truncated says the events were too many to read back: the counts are lower bounds.
	Truncated bool
}

// Simulate applies the changes inside a savepoint, reads their effect, and rolls
// everything back. authorize, if set, is asked before each change (the API checks
// the same privileges the real operation needs). A change that is refused
// returns an OpError and leaves nothing behind.
func (e Env) Simulate(changes []Change, authorize func(i int, c Change) error) (res *SimResult, err error) {
	if len(changes) == 0 {
		return nil, invalid("empty_simulation", "name at least one change")
	}
	if len(changes) > MaxSimChanges {
		return nil, invalid("too_many_changes", "a simulation has at most %d changes", MaxSimChanges)
	}
	sp, err := e.Tx.Savepoint()
	if err != nil {
		return nil, err
	}
	defer func() {
		if rerr := sp.Rollback(); rerr != nil {
			res, err = nil, errors.Join(err, rerr)
		}
	}()
	e.Engine = engine.New(SimBudget)
	before, err := e.Tx.GrpEventHead()
	if err != nil {
		return nil, err
	}
	out := &SimResult{}
	targeted := map[store.GroupID]bool{}
	for i, c := range changes {
		if authorize != nil {
			if err := authorize(i, c); err != nil {
				return nil, &OpError{Index: i, Err: err}
			}
		}
		sc, err := e.simulateOne(i, c)
		if err != nil {
			return nil, &OpError{Index: i, Err: err}
		}
		if g, err := e.Tx.GrpGroup(c.Group); err == nil {
			sc.Name = g.Name
		}
		targeted[c.Group] = true
		out.Changes = append(out.Changes, sc)
	}
	if err := e.simDiff(out, before.LastSeq, targeted); err != nil {
		return nil, err
	}
	return out, nil
}

func tooLarge(o Outcome) error {
	if !o.Queued {
		return nil
	}
	return invalid("simulation_too_large", "the change touches too many memberships to simulate (more than %d row operations)", SimBudget)
}

func (e Env) simulateOne(i int, c Change) (SimChange, error) {
	sc := SimChange{Index: i, Kind: c.Kind, Group: c.Group}
	switch c.Kind {
	case ChangeAddMember:
		r, err := e.AddMember(c.Group, MemberInput{Identity: c.Identity, Group: c.Member, EnabledFrom: c.EnabledFrom,
			DisabledAt: c.DisabledAt, Reason: c.Reason})
		if err != nil {
			return sc, err
		}
		sc.Status = BatchUpdated
		if r.Created {
			sc.Status = BatchCreated
		}
		if err := tooLarge(r.Outcome); err != nil {
			return sc, err
		}
	case ChangeRemoveMember:
		out, err := e.RemoveMember(c.Group, c.Remove)
		if err != nil {
			return sc, err
		}
		sc.Status = BatchRemoved
		if err := tooLarge(out); err != nil {
			return sc, err
		}
	case ChangeSetComposite, ChangeConvertToComposite:
		in := CompositeInput{Op: c.Op, Factors: c.Factors, DiscardMembers: c.DiscardMembers}
		var out Outcome
		var err error
		if c.Kind == ChangeSetComposite {
			_, out, err = e.SetComposite(c.Group, in)
		} else {
			_, out, err = e.ConvertToComposite(c.Group, in)
		}
		if err != nil {
			return sc, err
		}
		sc.Status = "definition"
		if err := tooLarge(out); err != nil {
			return sc, err
		}
	default:
		return sc, invalid("invalid_change", "a change is add_member, remove_member, set_composite or convert_to_composite")
	}
	return sc, nil
}

// simDiff reads the effective events written since seq and folds them into the
// per-group diff. An identity that enters and leaves again nets to nothing.
func (e Env) simDiff(out *SimResult, since int64, targeted map[store.GroupID]bool) error {
	head, err := e.Tx.GrpEventHead()
	if err != nil {
		return err
	}
	net := map[store.GroupID]map[int64]int{}
	scanned := 0
	for after := since; after < head.LastSeq; {
		batch, err := e.Tx.GrpEventsAfter(after, head.LastSeq, events.MaxBatch)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}
		for _, ev := range batch {
			after = ev.Seq
			if ev.Identity == nil || (ev.Type != events.MembershipEffectiveAdded && ev.Type != events.MembershipEffectiveRemoved) {
				continue
			}
			if scanned++; scanned > MaxSimEvents {
				out.Truncated = true
				break
			}
			g := store.GroupID(ev.ObjectID)
			if net[g] == nil {
				net[g] = map[int64]int{}
			}
			if ev.Type == events.MembershipEffectiveAdded {
				net[g][*ev.Identity]++
			} else {
				net[g][*ev.Identity]--
			}
		}
		if out.Truncated {
			break
		}
	}
	groups := make([]store.GroupID, 0, len(net))
	for g := range net {
		groups = append(groups, g)
	}
	for g := range targeted {
		if _, ok := net[g]; !ok {
			groups = append(groups, g)
		}
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)
	for _, g := range groups {
		grp, err := e.Tx.GrpGroup(g)
		if err != nil {
			return fmt.Errorf("simulation: group %s: %w", g, err)
		}
		sg := SimGroup{Group: g, Name: grp.Name, Targeted: targeted[g], After: grp.EffectiveCount}
		var added, removed []int64
		for id, n := range net[g] {
			switch {
			case n > 0:
				added = append(added, id)
			case n < 0:
				removed = append(removed, id)
			}
		}
		slices.Sort(added)
		slices.Sort(removed)
		sg.Added, sg.Removed = len(added), len(removed)
		sg.Before = sg.After - int64(sg.Added) + int64(sg.Removed)
		if sg.AddedSample, err = e.simSample(added); err != nil {
			return err
		}
		if sg.RemovedSample, err = e.simSample(removed); err != nil {
			return err
		}
		out.Added += sg.Added
		out.Removed += sg.Removed
		if sg.Added > 0 || sg.Removed > 0 || sg.Targeted {
			out.Groups = append(out.Groups, sg)
		}
	}
	// the groups the changes name come first, then the downstream ones, each by name
	slices.SortStableFunc(out.Groups, func(a, b SimGroup) int {
		switch {
		case a.Targeted != b.Targeted:
			if a.Targeted {
				return -1
			}
			return 1
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	return nil
}

func (e Env) simSample(ids []int64) ([]SimMember, error) {
	if len(ids) > SimSample {
		ids = ids[:SimSample]
	}
	out := make([]SimMember, 0, len(ids))
	for _, id := range ids {
		m := SimMember{Identity: id}
		if ident, err := e.Tx.Identity(id); err == nil {
			m.Name = ident.Name
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}
