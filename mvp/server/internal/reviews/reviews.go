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
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"

	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

// MaxCommentRunes caps a reviewer's comment (also the audit event's comment).
const MaxCommentRunes = 1000

// TargetType is the audit target type of review decision events; the target
// id is the review item id.
const TargetType = "review_item"

// Error is a caller error (mapped to HTTP 400).
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// ErrUnknownItem is returned for an item id that does not exist in the tenant
// (mapped to HTTP 404).
var ErrUnknownItem = &Error{"unknown review item"}

// ErrSelfReview refuses a decision by the item's own subject (mapped to HTTP
// 403, code self_review): nobody certifies their own access (issue #434).
var ErrSelfReview = &Error{"a reviewer cannot decide an item about themselves"}

// ErrReviewerUnlinked refuses a decision by a platform user with no linked
// identity (mapped to HTTP 403, code reviewer_unlinked): the self-review guard
// cannot prove such a person is not the subject, so it fails closed (issue #439).
var ErrReviewerUnlinked = &Error{"the reviewer's account is not linked to an identity"}

// refuseSelf returns ErrSelfReview when the decider is the item's subject: a
// platform user linked to the subject's identity, or the same person as one
// (SameActor). It returns ErrReviewerUnlinked for a platform user with no
// linked identity. A decider with no platform user (the scheduler) passes.
func refuseSelf(c *store.TenantTx, item *store.ReviewItem, by store.UserRef) error {
	return refuseSubject(c, item.IdentityID, by)
}

// refuseSubject is refuseSelf for a subject identity id (a review item or a
// sampled auto-decision).
func refuseSubject(c *store.TenantTx, subject int64, by store.UserRef) error {
	if by.ID == uuid.Nil {
		return nil
	}
	u, err := c.PlatformUser(by.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if u != nil && u.IdentityID == nil {
		return ErrReviewerUnlinked
	}
	users, err := c.PlatformUserIDsForIdentity(subject)
	if err != nil {
		return err
	}
	for _, u := range users {
		same, err := c.SameActor(by.ID.String(), u.String())
		if err != nil {
			return err
		}
		if same {
			return ErrSelfReview
		}
	}
	return nil
}

// avoidSelf keeps a subject from being their own reviewer: when the picked
// reviewer is the subject it returns the type's fallback reviewer (the
// escalation target), else the security lead, else nil.
func avoidSelf(r *Resolver, subject, reviewer, lead *store.Identity) *store.Identity {
	if reviewer == nil || reviewer.ID != subject.ID {
		return reviewer
	}
	if r != nil {
		if f := r.active(r.Settings.FallbackID); f != nil && f.ID != subject.ID {
			return f
		}
	}
	if lead != nil && lead.ID != subject.ID {
		return lead
	}
	return nil
}

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

// Scope narrows a campaign (issue #166): one system's grants (System, "" for
// every system) and, with PrivilegedOnly, privileged grants only.
//
// RoleIDs (issue #214) scopes the campaign to business roles: it then reviews
// every membership of those roles (and nothing else), whatever the risk, and
// System and PrivilegedOnly do not apply.
type Scope struct {
	System         string
	PrivilegedOnly bool
	// SkipEmpty creates no campaign when no grant is in scope (the campaign id is 0).
	SkipEmpty bool
	RoleIDs   []string
	// Resolver (issue #298) picks reviewers under a review type and limits the
	// campaign to the identities the type covers. Nil: the original reviewers.
	Resolver *Resolver
}

// GenerateCampaign creates a campaign with an item for every risky grant.
func GenerateCampaign(c *store.TenantTx, now time.Time, name string, unusedDays int, policies []*policy.Policy) (int64, error) {
	return GenerateScopedCampaign(c, now, name, unusedDays, policies, Scope{})
}

// GenerateScopedCampaign is GenerateCampaign over the grants in scope.
func GenerateScopedCampaign(c *store.TenantTx, now time.Time, name string, unusedDays int, policies []*policy.Policy, scope Scope) (int64, error) {
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

	rv, err := loadRoleView(c, scope)
	if err != nil {
		return 0, err
	}
	var pending []*store.ReviewItem
	total, items := 0, 0
	fz := newFreezer() // the population snapshot (issue #110), frozen below in this transaction
	if rv.scoped() {
		fz.roleScope = scope.RoleIDs
	}
	for _, iid := range g.Identities(true) {
		ident := people[iid]
		if scope.Resolver != nil && !scope.Resolver.Includes(ident) {
			continue
		}
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
			privileged := g.Node(ag.Dst).Privileged
			for _, ep := range via {
				privileged = privileged || ep.Privileged
			}
			just := rv.justifying(iid, ag)
			if len(just) == 0 && rv.scoped() {
				continue // a role-scoped campaign reviews memberships only
			}
			if len(just) == 0 || !rv.scoped() {
				if (scope.System != "" && g.Node(ag.Dst).System != scope.System) || (scope.PrivilegedOnly && !privileged) {
					continue
				}
			}
			if len(just) == 0 {
				total++ // a grant a role made is counted with its membership
			}
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
			if len(just) > 0 {
				// the role's grant is reviewed under its membership, not as an item
				rv.add(just, iid, reasons, g.Label(ag.Acct)+" → "+g.Label(ag.Dst), privileged, len(via), usedN, events, last,
					via, vnames)
				continue
			}
			if len(reasons) == 0 {
				fz.record(ident, g, ag, autoRule(now, unusedDays, len(via), usedN, last, privileged, ident))
				continue
			}
			fz.record(ident, g, ag, nil)
			var reviewer *store.Identity
			if ident.Type == "human" {
				if ident.ManagerID != nil {
					reviewer = people[*ident.ManagerID]
				}
			} else if owner != nil && owner.Status == "active" {
				reviewer = owner
			}
			if scope.Resolver != nil {
				if rr := scope.Resolver.ForGrant(ident, g.Node(ag.Dst)); rr != nil {
					reviewer = rr
				}
			}
			if reviewer == nil {
				reviewer = securityLead
			}
			reviewer = avoidSelf(scope.Resolver, ident, reviewer, securityLead)
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
			pending = append(pending, &store.ReviewItem{IdentityID: iid, EdgeID: &edgeID,
				EdgeSrc: ag.Acct, EdgeDst: ag.Dst, GrantLabel: g.Label(ag.Acct) + " → " + g.Label(ag.Dst), Reasons: reasons,
				Context: json.RawMessage(ctxJSON), ReviewerID: reviewerID})
			items++
		}
	}
	mTotal, mem, err := rv.build(now, people, securityLead)
	if err != nil {
		return 0, err
	}
	total, items = total+mTotal, items+len(mem)
	if total == 0 && scope.SkipEmpty {
		return 0, nil
	}
	campID, err := c.InsertCampaign(&store.ReviewCampaign{Name: name, CreatedAt: now, Status: "open", UnusedDays: unusedDays})
	if err != nil {
		return 0, err
	}
	for _, it := range pending {
		it.CampaignID = campID
		if err := c.InsertReviewItem(it); err != nil {
			return 0, err
		}
	}
	for _, m := range mem {
		m.item.CampaignID = campID
		if _, err := c.InsertMembershipItem(m.item, m.roleID, m.source); err != nil {
			return 0, err
		}
		fz.recordMembership(people[m.item.IdentityID], m.item, rv.roles[m.roleID].Name) // memberships are in the population (#365)
	}
	if err := c.SetCampaignTotals(campID, total, total-items); err != nil {
		return 0, err
	}
	if err := c.Audit(now, "system", "review.campaign_created", ojson.Object{{Key: "campaign", Value: name},
		{Key: "items", Value: items}, {Key: "total", Value: total}}); err != nil {
		return 0, err
	}
	var qaReviewer *int64 // sampled auto-decisions are QA'd by the security lead, not the line manager
	if securityLead != nil {
		qaReviewer = &securityLead.ID
	}
	_, err = fz.freeze(c, now, campID, unusedDays, qaReviewer)
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
//
// When the grant is a group membership in a system whose connection has
// write-back on, a revoke does not decide the item: it queues the removal in
// the target and returns the item still open. The provisioning engine decides
// the item and deletes the edge once a re-read confirms the member is gone; a
// failed or unverified write leaves the item open for the reviewer to retry.
func Decide(c *store.TenantTx, now time.Time, itemID int64, decision string, by store.UserRef, comment *string) (*store.ReviewItem, error) {
	if decision != "keep" && decision != "revoke" {
		return nil, &Error{"decision must be keep or revoke"}
	}
	if comment != nil && utf8.RuneCountInString(*comment) > MaxCommentRunes {
		return nil, &Error{fmt.Sprintf("comment must be at most %d characters", MaxCommentRunes)}
	}
	item, err := c.Item(itemID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnknownItem
	}
	if err != nil {
		return nil, err
	}
	if err := refuseSelf(c, item, by); err != nil {
		return nil, err
	}
	// A decided item is final. The same decision again is idempotent (nothing
	// is written); a different one is refused. The conditional update in
	// applyDecision closes the race between this read and the write.
	if done, rerr := resolved(item, decision); done {
		return item, rerr
	}
	key := fmt.Sprintf("review:%d:revoke", item.ID)
	if op, err := provision.InFlight(c, key); err != nil {
		return nil, err
	} else if op != nil {
		return nil, &Error{"a revoke for this item is waiting for the target system to confirm it"}
	}
	if decision == "revoke" {
		if routed, err := routeRevoke(c, now, item, key, by, comment); err != nil || routed {
			return item, err
		}
	}
	return applyDecision(c, now, item, decision, by, comment)
}

func applyDecision(c *store.TenantTx, now time.Time, item *store.ReviewItem, decision string, by store.UserRef, comment *string) (*store.ReviewItem, error) {
	applied, err := c.DecideItem(item.ID, decision, comment, now, by)
	if err != nil {
		return nil, err
	}
	if !applied { // decided by a concurrent request since the read
		if item, err = c.Item(item.ID); err != nil {
			return nil, err
		}
		if done, rerr := resolved(item, decision); done {
			return item, rerr
		}
		return nil, errors.New("review item decision was not applied")
	}
	item.Decision, item.Comment, item.DecidedAt = &decision, comment, &now
	if decision == "keep" {
		// a kept grant is intended access: record it, in this transaction
		if err := c.KeepIntent(item.EdgeSrc, item.EdgeDst, "review-item:"+strconv.FormatInt(item.ID, 10), now); err != nil {
			return nil, err
		}
	}
	if decision == "revoke" {
		if e, err := c.EdgeBetween(item.EdgeSrc, item.EdgeDst); err == nil {
			// an entitlement of an app with no connector becomes a manual task (issue #105)
			if err := flatfile.GrantRevoked(c, now, by.Display, e.ID, "review"); err != nil {
				return nil, err
			}
			if err := c.RevokeEdge(e.ID, now, "review"); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	det := ojson.Object{{Key: "item_id", Value: item.ID}, {Key: "grant", Value: item.GrantLabel}}
	if comment != nil && *comment != "" {
		det = append(det, ojson.KV{Key: "comment", Value: *comment})
	}
	if _, err := c.RecordAudit(store.AuditRecord{At: now, Action: "review." + decision, LegacyActor: by.Display,
		Detail: det, TargetType: TargetType, TargetID: strconv.FormatInt(item.ID, 10)}); err != nil {
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

// completeRevoke is the provisioning completion of a routed revoke.
const completeRevoke = "review.revoke"

type revokeData struct {
	ItemID  int64   `json:"item_id"`
	UserID  string  `json:"user_id,omitempty"`
	Display string  `json:"display"`
	Comment *string `json:"comment"`
}

func init() {
	provision.RegisterCompletion(completeRevoke, func(c *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d revokeData
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		item, err := c.Item(d.ItemID)
		if err != nil {
			return err
		}
		if item.Decision != nil && *item.Decision != "" {
			return nil // decided some other way meanwhile
		}
		by := store.UserRef{Display: d.Display}
		if d.UserID != "" {
			if by.ID, err = uuid.Parse(d.UserID); err != nil {
				return err
			}
		}
		_, err = applyDecision(c, now, item, "revoke", by, d.Comment)
		return err
	})
}

// routeRevoke queues the removal of the item's group membership in the target.
func routeRevoke(c *store.TenantTx, now time.Time, item *store.ReviewItem, key string, by store.UserRef, comment *string) (bool, error) {
	kind, aid, err := graph.ParseKey(item.EdgeSrc)
	if err != nil || kind != "account" {
		return false, nil
	}
	kind, gid, err := graph.ParseKey(item.EdgeDst)
	if err != nil || kind != "group" {
		return false, nil
	}
	a, err := c.Account(aid)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	g, err := c.Group(gid)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	d := revokeData{ItemID: item.ID, Display: by.Display, Comment: comment}
	if by.ID != uuid.Nil {
		d.UserID = by.ID.String()
	}
	_, routed, err := provision.Submit(c, now, provision.Change{System: g.System, Kind: target.RemoveEntitlement,
		Account: target.Account{Username: a.Username, ExternalID: a.ExternalID},
		Group:   target.Group{ExternalID: g.ExternalID, Name: g.Name}, Source: provision.SourceReview, Key: key,
		Completion: completeRevoke, Data: d})
	return routed, err
}
