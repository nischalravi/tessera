package reviews

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Role memberships in reviews (issue #214).
//
// A campaign certifies what a person holds through a business role as one
// item, the membership, with the grants the role made listed under it; those
// grants are not separate items. Revoking a manual or request membership
// removes it through roles.Unassign (its removal plan takes the role's grants
// no other role justifies). A rule member cannot be removed while the rule
// matches them, so the reviewer chooses: exclude them from the rule
// (roles.Exclude, a versioned and audited list that birthright evaluation
// honours) or flag the rule to the role owner (nothing is removed).
//
// A revoke of a grant a role made, still possible in campaigns generated
// before memberships were items, is converted into a revoke of the
// membership(s) that justify it. Refusing would leave the reviewer's decision
// unrecorded, and revoking only the edge would let Reconcile restore it; the
// conversion keeps the decision and makes it stick.

// Choices for revoking a rule membership.
const (
	ChoiceExclude = "exclude"
	ChoiceFlag    = "flag"
)

// ChoiceRequiredError: revoking a rule membership needs the reviewer to
// choose exclude or flag (mapped to HTTP 422).
type ChoiceRequiredError struct{ Role string }

func (e *ChoiceRequiredError) Error() string {
	return fmt.Sprintf("%s is assigned by a birthright rule that still matches this person: choose %q or %q",
		e.Role, ChoiceExclude, ChoiceFlag)
}

// ---------------------------------------------------------------- generation

type memberKey struct {
	identity int64
	role     string
}

type membership struct {
	reasons    map[string]bool
	grants     []string
	privileged bool
	perms      int
	used       int
	events     int
	last       *time.Time
	tags       map[string]bool
	violations map[string]bool
	samples    []string
}

// roleView is the role state a campaign generation reads.
type roleView struct {
	only    map[string]bool // scoped role ids; nil: not scoped
	roles   map[string]*store.BusinessRole
	groups  map[string]map[int64]bool // role -> group ids
	members map[int64]map[string]*store.RoleMember
	acc     map[memberKey]*membership
	// resolver, when set, picks the reviewer under a review type (types.go).
	resolver *Resolver
}

func (v *roleView) scoped() bool { return v.only != nil }

func loadRoleView(c *store.TenantTx, scope Scope) (*roleView, error) {
	v := &roleView{roles: map[string]*store.BusinessRole{}, groups: map[string]map[int64]bool{},
		members: map[int64]map[string]*store.RoleMember{}, acc: map[memberKey]*membership{}}
	rs, err := c.BusinessRoles()
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		v.roles[r.ID] = r
	}
	es, err := c.AllRoleEntitlements()
	if err != nil {
		return nil, err
	}
	for _, e := range es {
		if v.groups[e.RoleID] == nil {
			v.groups[e.RoleID] = map[int64]bool{}
		}
		v.groups[e.RoleID][e.GroupID] = true
	}
	ms, err := c.AllRoleMembers()
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		if v.members[m.IdentityID] == nil {
			v.members[m.IdentityID] = map[string]*store.RoleMember{}
		}
		v.members[m.IdentityID][m.RoleID] = m
	}
	v.resolver = scope.Resolver
	if len(scope.RoleIDs) > 0 {
		v.only = map[string]bool{}
		for _, id := range scope.RoleIDs {
			// a role retired since the schedule was saved has no members left to review
			if r := v.roles[id]; r != nil && r.Status == store.RoleActive {
				v.only[id] = true
			}
		}
	}
	return v, nil
}

// justifying returns the active roles (within the scope) through which the
// person holds a grant a role made: none for any other grant.
func (v *roleView) justifying(identity int64, ag graph.AccountGrant) []string {
	if ag.Edge.Source != "role" {
		return nil
	}
	kind, gid, err := graph.ParseKey(ag.Dst)
	if err != nil || kind != "group" {
		return nil
	}
	var out []string
	for rid := range v.members[identity] {
		if r := v.roles[rid]; r == nil || r.Status != store.RoleActive || !v.groups[rid][gid] {
			continue
		}
		if v.scoped() && !v.only[rid] {
			continue
		}
		out = append(out, rid)
	}
	sort.Strings(out)
	return out
}

func (v *roleView) entry(identity int64, role string) *membership {
	k := memberKey{identity, role}
	if v.acc[k] == nil {
		v.acc[k] = &membership{reasons: map[string]bool{}, tags: map[string]bool{}, violations: map[string]bool{}}
	}
	return v.acc[k]
}

// add records a role-made grant under the memberships that justify it.
func (v *roleView) add(roleIDs []string, identity int64, reasons []string, label string, privileged bool, perms, used, events int,
	last *time.Time, via []*graph.EffectivePermission, violations []string) {
	for _, rid := range roleIDs {
		m := v.entry(identity, rid)
		for _, r := range reasons {
			m.reasons[r] = true
		}
		m.grants = append(m.grants, label)
		m.privileged = m.privileged || privileged
		m.perms += perms
		m.used += used
		m.events += events
		if last != nil && (m.last == nil || last.After(*m.last)) {
			m.last = last
		}
		for _, ep := range via {
			for _, t := range ep.Tags {
				m.tags[t] = true
			}
			if len(m.samples) < 4 {
				m.samples = append(m.samples, ep.Action+" on "+ep.ResourceName)
			}
		}
		for _, n := range violations {
			m.violations[n] = true
		}
	}
}

// pendingMembership is a membership item built but not yet inserted: the
// campaign row is created only once the scope is known to hold something.
type pendingMembership struct {
	item           *store.ReviewItem
	roleID, source string
}

// build returns the units reviewed and the membership items to insert (the
// rest are auto-certified).
func (v *roleView) build(now time.Time, people map[int64]*store.Identity,
	securityLead *store.Identity) (total int, out []pendingMembership, err error) {
	if v.scoped() { // every member of a scoped role is certified, with or without risky grants
		for iid, ms := range v.members {
			for rid := range ms {
				if v.only[rid] {
					v.entry(iid, rid)
				}
			}
		}
	}
	keys := make([]memberKey, 0, len(v.acc))
	for k := range v.acc {
		if people[k.identity] != nil {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].identity != keys[j].identity {
			return keys[i].identity < keys[j].identity
		}
		return v.roles[keys[i].role].Name < v.roles[keys[j].role].Name
	})
	for _, k := range keys {
		m, ident, role, mem := v.acc[k], people[k.identity], v.roles[k.role], v.members[k.identity][k.role]
		total++
		if ident.Status == "terminated" {
			m.reasons["terminated_identity"] = true
		}
		if len(m.reasons) == 0 && v.scoped() {
			m.reasons["role_review"] = true
		}
		if len(m.reasons) == 0 {
			continue
		}
		reasons := make([]string, 0, len(m.reasons))
		for r := range m.reasons {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		var daysSince any
		if m.last != nil {
			daysSince = timeutil.Days(now, *m.last)
		}
		grants := m.grants
		if grants == nil {
			grants = []string{}
		}
		ctx := ojson.Object{
			{Key: "permissions", Value: m.perms},
			{Key: "permissions_used", Value: m.used},
			{Key: "last_used", Value: timeutil.ISOPtr(m.last)},
			{Key: "days_since_used", Value: daysSince},
			{Key: "events_90d", Value: m.events},
			{Key: "privileged", Value: m.privileged},
			{Key: "sensitive", Value: sortedSet(m.tags)},
			{Key: "violations", Value: sortedSet(m.violations)},
			{Key: "peer_coverage", Value: nil},
			{Key: "sample_permissions", Value: append([]string{}, m.samples...)},
			{Key: "membership", Value: ojson.Object{{Key: "role_id", Value: role.ID}, {Key: "role", Value: role.Name},
				{Key: "source", Value: mem.Source}, {Key: "assigned_at", Value: timeutil.ISO(mem.AssignedAt)},
				{Key: "grants", Value: grants}}},
		}
		ctxJSON, err := store.JSON(ctx)
		if err != nil {
			return 0, nil, err
		}
		reviewer := securityLead
		if ident.Type == "human" {
			if ident.ManagerID != nil && people[*ident.ManagerID] != nil {
				reviewer = people[*ident.ManagerID]
			}
		} else if ident.OwnerID != nil && people[*ident.OwnerID] != nil && people[*ident.OwnerID].Status == "active" {
			reviewer = people[*ident.OwnerID]
		}
		if v.resolver != nil {
			if rr := v.resolver.ForRole(role); rr != nil {
				reviewer = rr
			}
		}
		reviewer = avoidSelf(v.resolver, ident, reviewer, securityLead)
		var reviewerID *int64
		if reviewer != nil {
			reviewerID = &reviewer.ID
		}
		out = append(out, pendingMembership{item: &store.ReviewItem{IdentityID: k.identity,
			EdgeSrc: "role:" + role.ID, EdgeDst: "identity:" + strconv.FormatInt(k.identity, 10),
			GrantLabel: "Role " + role.Name + " → " + ident.Name, Reasons: reasons, Context: json.RawMessage(ctxJSON),
			ReviewerID: reviewerID}, roleID: role.ID, source: mem.Source})
	}
	return total, out, nil
}

// ValidateRoleScope checks the roles a schedule is scoped to: each exists and
// is active. It returns them without duplicates.
func ValidateRoleScope(c *store.TenantTx, ids []string) ([]string, error) {
	if len(ids) > 50 {
		return nil, specErr("invalid_roles", "a review covers at most 50 roles")
	}
	out := []string{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || containsStr(out, id) {
			continue
		}
		r, err := c.BusinessRole(id)
		if errors.Is(err, store.ErrNotFound) || (err == nil && r.Status != store.RoleActive) {
			return nil, specErr("invalid_roles", "role %s is unknown or retired", id)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- decisions

// DecideItem is Decide for every kind of item. A role membership is certified
// as a membership; a revoke of a grant a role made becomes a revoke of the
// membership that justifies it; any other item is decided by Decide. choice
// (exclude or flag) applies to a rule membership being revoked and is ignored
// otherwise. resolution says what a role-backed revoke did ("" for a grant).
func DecideItem(c *store.TenantTx, now time.Time, itemID int64, decision string, by store.UserRef, comment *string,
	choice string) (item *store.ReviewItem, resolution string, err error) {
	if decision != "keep" && decision != "revoke" {
		return nil, "", &Error{"decision must be keep or revoke"}
	}
	if choice != "" && choice != ChoiceExclude && choice != ChoiceFlag {
		return nil, "", &Error{"rule_action must be exclude or flag"}
	}
	item, err = c.Item(itemID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", ErrUnknownItem
	}
	if err != nil {
		return nil, "", err
	}
	if err := refuseSelf(c, item, by); err != nil {
		return nil, "", err
	}
	if err := refuseHeldUndecided(c, item); err != nil {
		return nil, "", err
	}
	// A decided item is final, as in Decide: the same decision again is a
	// no-op, a different one is a *DecidedError.
	if done, rerr := resolved(item, decision); done {
		return item, "", rerr
	}
	ir, err := c.ReviewItemRole(itemID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, "", err
	}
	if ir != nil {
		return decideMembership(c, now, item, ir.RoleID, decision, by, comment, choice)
	}
	if decision == "revoke" && (item.Decision == nil || *item.Decision == "") {
		if just, err := roleGrantJustification(c, item, now); err != nil {
			return nil, "", err
		} else if len(just) > 0 {
			return decideConverted(c, now, item, just, by, comment, choice)
		}
	}
	item, err = Decide(c, now, itemID, decision, by, comment)
	return item, "", err
}

// roleGrantJustification returns the roles whose membership justifies the
// item's grant, when the grant is one a role made.
func roleGrantJustification(c *store.TenantTx, item *store.ReviewItem, now time.Time) ([]roles.Justification, error) {
	e, err := c.EdgeBetween(item.EdgeSrc, item.EdgeDst)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kind, gid, perr := graph.ParseKey(item.EdgeDst)
	if e.Source != "role" || perr != nil || kind != "group" {
		return nil, nil
	}
	return roles.Justifying(c, item.IdentityID, gid, now)
}

func actorOf(by store.UserRef) roles.Actor { return roles.Actor{UserID: by.ID, Display: by.Display} }

// reasonOf is the reason the role service records for a review revoke.
func reasonOf(itemID int64, comment *string) string {
	r := ""
	if comment != nil {
		r = strings.TrimSpace(*comment)
	}
	if r == "" {
		r = fmt.Sprintf("Revoked in access review (item %d)", itemID)
	}
	if rs := []rune(r); len(rs) > roles.MaxReason {
		r = string(rs[:roles.MaxReason])
	}
	return r
}

// revokeMembership removes (or, for a rule member, excludes or flags) one
// membership for a review decision and returns what it did.
func revokeMembership(c *store.TenantTx, now time.Time, itemID int64, roleID string, identityID int64, by store.UserRef,
	comment *string, choice string) (string, error) {
	role, err := c.BusinessRole(roleID)
	if errors.Is(err, store.ErrNotFound) {
		return ResolveGone, nil
	}
	if err != nil {
		return "", err
	}
	ms, err := c.RoleMembers(roleID)
	if err != nil {
		return "", err
	}
	var m *store.RoleMember
	for _, x := range ms {
		if x.IdentityID == identityID {
			m = x
		}
	}
	if m == nil {
		return ResolveGone, nil // already removed elsewhere
	}
	reason, actor := reasonOf(itemID, comment), actorOf(by)
	if m.Source != store.MemberRule {
		_, err := roles.Unassign(c, roleID, identityID, reason, actor, false, now)
		return store.ResolveUnassign, err
	}
	switch choice {
	case ChoiceExclude:
		_, err := roles.Exclude(c, roleID, identityID, reason, &itemID, actor, false, now)
		return store.ResolveExclude, err
	case ChoiceFlag:
		d := ojson.Object{{Key: "item_id", Value: itemID}, {Key: "role_id", Value: roleID}, {Key: "role", Value: role.Name},
			{Key: "identity_id", Value: identityID}, {Key: "reason", Value: reason}}
		if role.OwnerIdentityID != nil {
			d = append(d, ojson.KV{Key: "owner_identity_id", Value: *role.OwnerIdentityID})
		}
		return store.ResolveFlag, c.Audit(now, by.Display, "review.rule_flagged", d)
	}
	return "", &ChoiceRequiredError{Role: role.Name}
}

// ResolveGone: the membership was already removed when the reviewer decided.
const ResolveGone = "gone"

func decideMembership(c *store.TenantTx, now time.Time, item *store.ReviewItem, roleID, decision string, by store.UserRef,
	comment *string, choice string) (*store.ReviewItem, string, error) {
	if item.Decision != nil && *item.Decision != "" {
		return nil, "", &Error{"review item already decided"}
	}
	resolution := ""
	if decision == "revoke" {
		var err error
		if resolution, err = revokeMembership(c, now, item.ID, roleID, item.IdentityID, by, comment, choice); err != nil {
			return nil, "", err
		}
	}
	stored := resolution
	if stored == ResolveGone {
		stored = ""
	}
	if err := finishItem(c, now, item, decision, by, comment, stored, resolution); err != nil {
		return nil, "", err
	}
	return item, resolution, nil
}

// decideConverted is the revoke of a grant a role made: it revokes the
// membership(s) that justify it.
//
// It deliberately does not go through routeRevoke (the write-back queue Decide
// uses): the role, not the edge, is what is removed, roles.Unassign/Exclude
// drop the role's grants in Tessera only (as every role change does today),
// and queueing a target removal of just this edge would leave the item open
// and let Reconcile restore the grant. Writing role removals back to the
// target is a separate change to the roles engine.
func decideConverted(c *store.TenantTx, now time.Time, item *store.ReviewItem, just []roles.Justification, by store.UserRef,
	comment *string, choice string) (*store.ReviewItem, string, error) {
	resolution := ""
	for _, j := range just {
		r, err := revokeMembership(c, now, item.ID, j.Role.ID, item.IdentityID, by, comment, choice)
		if err != nil {
			return nil, "", err
		}
		if resolution == "" || r == store.ResolveFlag {
			resolution = r
		}
	}
	if err := finishItem(c, now, item, "revoke", by, comment, "", resolution); err != nil {
		return nil, "", err
	}
	return item, resolution, nil
}

// finishItem records the decision (once), audits it and completes the
// campaign when nothing is left open. stored is the resolution kept on a
// membership item; detail is what the audit event reports.
func finishItem(c *store.TenantTx, now time.Time, item *store.ReviewItem, decision string, by store.UserRef, comment *string,
	stored, detail string) error {
	applied, err := c.DecideMembershipItem(item.ID, decision, comment, now, by, stored)
	if err != nil {
		return err
	}
	if !applied {
		return &Error{"review item already decided"}
	}
	item.Decision, item.Comment, item.DecidedAt = &decision, comment, &now
	d := ojson.Object{{Key: "item_id", Value: item.ID}, {Key: "grant", Value: item.GrantLabel}}
	if detail != "" {
		d = append(d, ojson.KV{Key: "resolution", Value: detail})
	}
	if comment != nil && *comment != "" {
		d = append(d, ojson.KV{Key: "comment", Value: *comment})
	}
	if err := c.Audit(now, by.Display, "review."+decision, d); err != nil {
		return err
	}
	open, err := c.CountOpenItems(item.CampaignID)
	if err != nil {
		return err
	}
	if open == 0 {
		return c.CompleteCampaign(item.CampaignID)
	}
	return nil
}
