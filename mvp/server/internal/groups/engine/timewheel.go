package engine

import (
	"cmp"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The time wheel (design §6.4). Direct memberships and groups carry
// enabled_from and disabled_at; a membership starts or stops counting when its
// date passes, which nothing else notices. The Runner calls Tick every 30
// seconds (and wakes at the next boundary, NextBoundary), so a disabled date
// takes effect within 60 seconds. Authorization does not wait for it:
// IsMember re-checks the rows' own dates.
//
// Tick applies every boundary in (wheel_at, now], then moves wheel_at to now.
// Boundaries are found through the partial indexes on the date columns.

// TickResult summarizes one Tick.
type TickResult struct {
	Rows    int // direct memberships whose enabled_from or disabled_at passed
	Groups  int // groups whose enabled_from or disabled_at passed
	Changes int // effective changes made inline
	Queued  int // groups whose recompute was queued instead
}

// Tick applies the dates that passed since the last tick. The first call only
// sets the starting point.
func (e *Engine) Tick(tx *store.TenantTx, now time.Time) (TickResult, error) {
	var res TickResult
	st, err := tx.GrpEngineState()
	if err != nil {
		return res, err
	}
	if st.WheelAt == nil || !now.After(*st.WheelAt) {
		if st.WheelAt == nil {
			return res, tx.SetGrpWheelAt(now)
		}
		return res, nil
	}
	from := *st.WheelAt
	var rows []*store.DirectMembership
	en, err := tx.GrpDirectEnabledIn(from, now)
	if err != nil {
		return res, err
	}
	dis, err := tx.GrpDirectDisabledIn(from, now)
	if err != nil {
		return res, err
	}
	rows = append(en, dis...)
	seedSet := map[Seed]struct{}{}
	recompute := map[store.GroupID]struct{}{}
	for _, m := range rows {
		if m.MemberType == store.MemberIdentity && m.MemberIdentity != nil {
			seedSet[Seed{m.GroupID, m.ListID, *m.MemberIdentity}] = struct{}{}
		} else {
			recompute[m.GroupID] = struct{}{} // a nested group's whole membership is affected
		}
	}
	res.Rows = len(rows)
	gen, err := tx.GrpGroupsEnabledIn(from, now)
	if err != nil {
		return res, err
	}
	gdis, err := tx.GrpGroupsDisabledIn(from, now)
	if err != nil {
		return res, err
	}
	for _, g := range gen {
		recompute[g.ID] = struct{}{}
	}
	for _, g := range gdis {
		recompute[g.ID] = struct{}{}
		if g.Status == store.GroupActive { // the date becomes a status change
			g.Status = store.GroupDisabled
			if err := tx.UpdateGrpGroup(g); err != nil {
				return res, err
			}
			factors, err := tx.GrpFactors(g.ID)
			if err != nil {
				return res, err
			}
			ev := events.New(events.GroupDisabled, string(g.ID), now, store.CauseTimewheel)
			ev.Data = pit.ObjectData(pit.GroupSnapshot(g, factors), nil)
			if err := pit.Emit(tx, ev); err != nil {
				return res, err
			}
		}
	}
	res.Groups = len(gen) + len(gdis)

	if int64(len(seedSet)) > e.budget() { // too many to do here: recompute their groups instead
		for s := range seedSet {
			recompute[s.Group] = struct{}{}
		}
		seedSet = nil
	}
	seeds := make([]Seed, 0, len(seedSet))
	for s := range seedSet {
		seeds = append(seeds, s)
	}
	slices.SortFunc(seeds, func(a, b Seed) int {
		return cmp.Or(cmp.Compare(a.Group, b.Group), cmp.Compare(a.List, b.List), cmp.Compare(a.Identity, b.Identity))
	})
	changes, err := e.applyAs(tx, now, seeds, store.CauseTimewheel)
	if err != nil {
		return res, err
	}
	res.Changes = len(changes)
	groups := make([]store.GroupID, 0, len(recompute))
	for g := range recompute {
		groups = append(groups, g)
	}
	slices.Sort(groups)
	for _, g := range groups {
		out, err := e.RecomputeGroup(tx, now, g)
		if err != nil {
			return res, err
		}
		if out.Queued {
			res.Queued++
		}
	}
	if err := tx.SetGrpWheelAt(now); err != nil {
		return res, err
	}
	if res.Rows+res.Groups > 0 {
		err = tx.Audit(now, "groups.engine", "groups.timewheel.applied", ojson.Object{
			{Key: "rows", Value: int64(res.Rows)}, {Key: "groups", Value: int64(res.Groups)},
			{Key: "changes", Value: int64(res.Changes)}, {Key: "queued", Value: int64(res.Queued)}})
	}
	return res, err
}

// NextBoundary is the earliest date after now at which the wheel has work, or
// nil. The Runner sleeps until then if that is sooner than its next tick.
func NextBoundary(tx *store.TenantTx, now time.Time) (*time.Time, error) {
	return tx.GrpNextBoundary(now)
}
