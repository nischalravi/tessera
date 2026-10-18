// Package reviews builds exception-only access review campaigns.
//
// Rather than asking managers to rubber-stamp every grant, a campaign only
// contains grants that are risky: unused, implicated in a policy violation,
// held by an orphaned NHI or a leaver, or privileged and not recently used.
// Everything else is auto-certified with the evidence recorded.
package reviews

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

// Error is a caller error (mapped to HTTP 400).
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// ErrUnknownItem is returned for an item id that does not exist in the tenant
// (mapped to HTTP 404).
var ErrUnknownItem = &Error{"unknown review item"}

type deptTarget struct {
	dept string
	null bool
	dst  string
}

func deptKey(d *string) (string, bool) {
	if d == nil {
		return "", true
	}
	return *d, false
}

// GenerateCampaign creates a campaign with an item for every risky grant.
func GenerateCampaign(c *store.TenantTx, now time.Time, name string, unusedDays int, policies []*policy.Policy) (int64, error) {
	g, err := graph.Build(c, now)
	if err != nil {
		return 0, err
	}
	u, err := usage.Build(c, now)
	if err != nil {
		return 0, err
	}
	violations, err := policy.Evaluate(policies, policy.NewContext(g, c, now))
	if err != nil {
		return 0, err
	}
	violEdges := map[[2]string][]string{}
	for _, v := range violations {
		for _, e := range v.Edges {
			k := [2]string{e[0], e[1]}
			violEdges[k] = append(violEdges[k], v.PolicyName)
		}
	}
	people, all, err := c.IdentityMap()
	if err != nil {
		return 0, err
	}
	var securityLead *store.Identity
	for _, i := range all {
		if i.Title != nil && *i.Title == "Head of Security" {
			securityLead = i
			break
		}
	}
	// peer coverage: how common is each grant target within a department
	type deptK struct {
		dept string
		null bool
	}
	deptSizes := map[deptK]int{}
	for _, i := range all {
		if i.Type == "human" && i.Status == "active" {
			d, null := deptKey(i.Department)
			deptSizes[deptK{d, null}]++
		}
	}
	targetByDept := map[deptTarget]int{}
	for _, iid := range g.Identities(true) {
		d, null := deptKey(people[iid].Department)
		for _, ag := range g.GrantEdgesFromAccounts(iid) {
			targetByDept[deptTarget{d, null, ag.Dst}]++
		}
	}

	campID, err := c.InsertCampaign(&store.ReviewCampaign{Name: name, CreatedAt: now, Status: "open", UnusedDays: unusedDays})
	if err != nil {
		return 0, err
	}
	total, items := 0, 0
	for _, iid := range g.Identities(true) {
		ident := people[iid]
		eff := g.EffectivePermissions(iid)
		var owner *store.Identity
		if ident.OwnerID != nil {
			owner = people[*ident.OwnerID]
		}
		for _, ag := range g.GrantEdgesFromAccounts(iid) {
			if ag.Edge.EdgeID == nil || ag.Edge.Source == "jit" {
				continue
			}
			if g.Node(ag.Acct).Status != "active" {
				continue
			}
			edge := [2]string{ag.Acct, ag.Dst}
			via := graph.PermsViaEdge(eff, edge)
			if len(via) == 0 {
				continue
			}
			total++
			var last *time.Time
			usedN, events := 0, 0
			for _, ep := range via {
				s := u.Get(iid, ep.PermID)
				events += s.Events90d
				if s.LastUsed != nil {
					if timeutil.Days(now, *s.LastUsed) < unusedDays {
						usedN++
					}
					if last == nil || s.LastUsed.After(*last) {
						last = s.LastUsed
					}
				}
			}
			reasons := []string{}
			if usedN == 0 {
				reasons = append(reasons, fmt.Sprintf("unused_%dd", unusedDays))
			}
			privileged := g.Node(ag.Dst).Privileged
			for _, ep := range via {
				privileged = privileged || ep.Privileged
			}
			if privileged && (last == nil || timeutil.Days(now, *last) >= 30) {
				reasons = append(reasons, "privileged_idle")
			}
			vnames, inViol := violEdges[edge]
			if inViol {
				reasons = append(reasons, "policy_violation")
			}
			if ident.Status == "terminated" {
				reasons = append(reasons, "terminated_identity")
			}
			if ident.Type != "human" && (owner == nil || owner.Status != "active") {
				reasons = append(reasons, "orphaned_nhi")
			}
			if len(reasons) == 0 {
				continue
			}
			var reviewer *store.Identity
			if ident.Type == "human" {
				if ident.ManagerID != nil {
					reviewer = people[*ident.ManagerID]
				}
			} else if owner != nil && owner.Status == "active" {
				reviewer = owner
			}
			if reviewer == nil {
				reviewer = securityLead
			}
			d, null := deptKey(ident.Department)
			deptN := deptSizes[deptK{d, null}]
			peers := targetByDept[deptTarget{d, null, ag.Dst}]
			var coverage any
			if ident.Type == "human" && deptN != 0 {
				coverage = ojson.Float(timeutil.Round(float64(peers)/float64(deptN), 2))
			}
			tagSet := map[string]bool{}
			for _, ep := range via {
				for _, t := range ep.Tags {
					tagSet[t] = true
				}
			}
			violSet := map[string]bool{}
			for _, n := range vnames {
				violSet[n] = true
			}
			samples := []string{}
			for i, ep := range via {
				if i == 4 {
					break
				}
				samples = append(samples, ep.Action+" on "+ep.ResourceName)
			}
			var daysSince any
			if last != nil {
				daysSince = timeutil.Days(now, *last)
			}
			ctx := ojson.Object{
				{Key: "permissions", Value: len(via)},
				{Key: "permissions_used", Value: usedN},
				{Key: "last_used", Value: timeutil.ISOPtr(last)},
				{Key: "days_since_used", Value: daysSince},
				{Key: "events_90d", Value: events},
				{Key: "privileged", Value: privileged},
				{Key: "sensitive", Value: sortedSet(tagSet)},
				{Key: "violations", Value: sortedSet(violSet)},
				{Key: "peer_coverage", Value: coverage},
				{Key: "sample_permissions", Value: samples},
			}
			ctxJSON, err := store.JSON(ctx)
			if err != nil {
				return 0, err
			}
			var reviewerID *int64
			if reviewer != nil {
				reviewerID = &reviewer.ID
			}
			edgeID := *ag.Edge.EdgeID
			if err := c.InsertReviewItem(&store.ReviewItem{CampaignID: campID, IdentityID: iid, EdgeID: &edgeID,
				EdgeSrc: ag.Acct, EdgeDst: ag.Dst, GrantLabel: g.Label(ag.Acct) + " → " + g.Label(ag.Dst), Reasons: reasons,
				Context: json.RawMessage(ctxJSON), ReviewerID: reviewerID}); err != nil {
				return 0, err
			}
			items++
		}
	}
	if err := c.SetCampaignTotals(campID, total, total-items); err != nil {
		return 0, err
	}
	err = c.Audit(now, "system", "review.campaign_created", ojson.Object{{Key: "campaign", Value: name},
		{Key: "items", Value: items}, {Key: "total", Value: total}})
	return campID, err
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DecidedError refuses a decision that differs from the one already applied
// to the item (mapped to HTTP 409, code review_item_decided).
type DecidedError struct {
	ItemID    int64
	Current   string
	Requested string
}

func (e *DecidedError) Error() string {
	return fmt.Sprintf("review item already decided as %s", e.Current)
}

// resolved reports whether the item already has a decision: with a nil error
// when it equals the requested one (idempotent), else with a DecidedError.
func resolved(item *store.ReviewItem, requested string) (bool, error) {
	if item.Decision == nil || *item.Decision == "" {
		return false, nil
	}
	if *item.Decision == requested {
		return true, nil
	}
	return true, &DecidedError{ItemID: item.ID, Current: *item.Decision, Requested: requested}
}

// Decide records keep/revoke on an item; revoke deletes the grant edge.
// by is the reviewer (the request's principal). A decided item is final:
// repeating the same decision is a no-op, a different one is a *DecidedError
// (the item is returned too, so the caller can report it).
func Decide(c *store.TenantTx, now time.Time, itemID int64, decision string, by store.UserRef, comment *string) (*store.ReviewItem, error) {
	if decision != "keep" && decision != "revoke" {
		return nil, &Error{"decision must be keep or revoke"}
	}
	item, err := c.Item(itemID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnknownItem
	}
	if err != nil {
		return nil, err
	}
	// A decided item is final. The same decision again is idempotent (nothing
	// is written); a different one is refused. The conditional update below
	// closes the race between this read and the write.
	if done, rerr := resolved(item, decision); done {
		return item, rerr
	}
	applied, err := c.DecideItem(item.ID, decision, comment, now, by)
	if err != nil {
		return nil, err
	}
	if !applied { // decided by a concurrent request since the read
		if item, err = c.Item(itemID); err != nil {
			return nil, err
		}
		if done, rerr := resolved(item, decision); done {
			return item, rerr
		}
		return nil, errors.New("review item decision was not applied")
	}
	item.Decision, item.Comment, item.DecidedAt = &decision, comment, &now
	if decision == "revoke" {
		if e, err := c.EdgeBetween(item.EdgeSrc, item.EdgeDst); err == nil {
			if err := c.RevokeEdge(e.ID, now, "review"); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	if err := c.Audit(now, by.Display, "review."+decision, ojson.Object{{Key: "item_id", Value: item.ID},
		{Key: "grant", Value: item.GrantLabel}}); err != nil {
		return nil, err
	}
	open, err := c.CountOpenItems(item.CampaignID)
	if err != nil {
		return nil, err
	}
	if open == 0 {
		if err := c.CompleteCampaign(item.CampaignID); err != nil {
			return nil, err
		}
		if err := notify.ReviewClosed(c, now, item.CampaignID); err != nil {
			return nil, err
		}
	}
	return item, nil
}
