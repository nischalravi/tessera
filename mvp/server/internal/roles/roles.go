// Package roles is the business role service (issue #161): a role bundles
// entitlements (groups) across connections, with an owner, a description,
// a risk and an optional birthright rule.
//
// Holding a role grants its entitlements in Tessera: a grant edge, source
// "role", from the member's account to each group (the account the request
// service would use, jit.AccountFor). An edge granted any other way
// (connector, request, manual, JIT) is never touched, and a role edge is
// removed only when none of the person's roles still grants the group, so
// overlapping roles and direct grants are safe.
//
// Every change (create, update, retire, assign, unassign, reconcile, an
// approved role request) is computed as a Plan first: the grants to add,
// the role grants to remove and the grants kept, with why. A dry run returns
// the plan and changes nothing; otherwise the plan is applied, the role is
// versioned (create, update, retire) and an audit event records the change
// and its plan, all in the caller's transaction.
//
// Members come from three sources: the birthright rule (kept in step with
// the rule by every save and by Reconcile), an approved request, or a manual
// assignment. A rule member is removed by changing the rule, not by hand.
//
// Drift reports members missing an entitlement (no account in the system,
// or the grant was removed elsewhere) and people who hold most or all of a
// role's entitlements without the role (candidates to assign).
package roles

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/abac"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits.
const (
	MaxName         = 120
	MaxDescription  = 2000
	MaxEntitlements = 100
	MaxRuleValues   = 50
	MaxReason       = requests.MaxReason
	MaxJustify      = requests.MaxJustification
)

// Error is a refused change; Code is stable for API clients.
type Error = requests.Error

// Actor is the signed-in user acting (the request service's actor).
type Actor = requests.Actor

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------- rule

// Rule is a birthright rule: an active identity matches when, for every
// non-empty list, its attribute is in the list and, if the rule names an
// attribute policy (issue #162), the policy's condition holds for the person.
// A missing attribute fails the policy.
type Rule struct {
	Department []string `json:"department,omitempty"`
	Type       []string `json:"type,omitempty"`
	Title      []string `json:"title,omitempty"`
	Policy     string   `json:"policy,omitempty"` // id of an abac policy
}

func (r *Rule) empty() bool {
	return r == nil || (len(r.Department) == 0 && len(r.Type) == 0 && len(r.Title) == 0 && r.Policy == "")
}

func clean(vs []string) []string {
	out := []string{}
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func (r *Rule) normalized() *Rule {
	if r == nil {
		return nil
	}
	n := &Rule{Department: clean(r.Department), Type: clean(r.Type), Title: clean(r.Title), Policy: strings.TrimSpace(r.Policy)}
	if n.empty() {
		return nil
	}
	return n
}

// Matches reports whether the identity is active and matches every list. A
// rule that names a policy never matches here (use Match with its condition).
func (r *Rule) Matches(i *store.Identity) bool {
	if r.empty() || r.Policy != "" || i.Status != "active" {
		return false
	}
	return r.lists(i)
}

func (r *Rule) lists(i *store.Identity) bool {
	in := func(list []string, v *string) bool { return len(list) == 0 || (v != nil && slices.Contains(list, *v)) }
	t := i.Type
	return in(r.Department, i.Department) && in(r.Type, &t) && in(r.Title, i.Title)
}

// Match reports whether the identity is active, matches every list and, when
// the rule names a policy, satisfies cond (the policy's condition, nil when
// the policy is missing or retired: then nothing matches) with attrs.
func (r *Rule) Match(i *store.Identity, cond *abac.Node, attrs abac.Attrs) bool {
	if r.empty() || i.Status != "active" || !r.lists(i) {
		return false
	}
	return r.Policy == "" || abac.Eval(cond, attrs)
}

// ParseRule reads a stored rule (nil: no rule).
func ParseRule(s *string) (*Rule, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	var r Rule
	if err := json.Unmarshal([]byte(*s), &r); err != nil {
		return nil, fmt.Errorf("roles: birthright rule: %w", err)
	}
	return r.normalized(), nil
}

func ruleJSON(r *Rule) (*string, error) {
	if r.empty() {
		return nil, nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	s := string(b)
	return &s, nil
}

// ---------------------------------------------------------------- spec

// Spec is a role's editable content.
type Spec struct {
	Name            string
	Description     string
	OwnerIdentityID *int64
	Risk            string
	Requestable     bool
	Birthright      *Rule
	Entitlements    []int64 // group ids
	Note            string  // why the change was made (kept in the version)
}

func (w *world) validate(s *Spec, selfID string) error {
	s.Name, s.Description, s.Note = strings.TrimSpace(s.Name), strings.TrimSpace(s.Description), strings.TrimSpace(s.Note)
	s.Birthright = s.Birthright.normalized()
	switch {
	case s.Name == "" || len(s.Name) > MaxName:
		return refuse(422, "invalid_name", "a name of 1 to %d characters is required", MaxName)
	case len(s.Description) > MaxDescription:
		return refuse(422, "invalid_description", "the description is at most %d characters", MaxDescription)
	case !slices.Contains(requests.Risks, s.Risk):
		return refuse(422, "invalid_risk", "risk is low, medium or high")
	case len(s.Note) > MaxReason:
		return refuse(422, "invalid_note", "the note is at most %d characters", MaxReason)
	case len(s.Entitlements) == 0:
		return refuse(422, "no_entitlements", "a role grants at least one entitlement")
	case len(s.Entitlements) > MaxEntitlements:
		return refuse(422, "too_many_entitlements", "a role grants at most %d entitlements", MaxEntitlements)
	}
	if r := s.Birthright; r != nil {
		if r.Policy != "" {
			if p, err := w.tx.AbacPolicy(r.Policy); errors.Is(err, store.ErrNotFound) {
				return refuse(422, "invalid_rule", "attribute policy not found")
			} else if err != nil {
				return err
			} else if p.Status != store.AbacActive {
				return refuse(422, "invalid_rule", "attribute policy %s is retired", p.Name)
			}
		}
		if len(r.Department)+len(r.Type)+len(r.Title) > MaxRuleValues {
			return refuse(422, "invalid_rule", "a rule lists at most %d values", MaxRuleValues)
		}
		for _, t := range r.Type {
			if !slices.Contains(requests.IdentityTypes, t) {
				return refuse(422, "invalid_rule", "unknown identity type %q", t)
			}
		}
	}
	if other, err := w.tx.BusinessRoleByName(s.Name); err == nil && other.ID != selfID {
		return refuse(409, "name_taken", "a role named %q exists", s.Name)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if s.OwnerIdentityID != nil {
		o, err := w.identity(*s.OwnerIdentityID)
		if err != nil {
			return err
		}
		if o == nil {
			return refuse(422, "owner_not_found", "owner not found")
		}
		if o.Status != "active" {
			return refuse(422, "owner_not_active", "%s is not active", o.Name)
		}
	}
	gs := slices.Clone(s.Entitlements)
	slices.Sort(gs)
	s.Entitlements = slices.Compact(gs)
	for _, gid := range s.Entitlements {
		g, err := w.group(gid)
		if err != nil {
			return err
		}
		if g == nil {
			return refuse(422, "group_not_found", "entitlement %d not found", gid)
		}
	}
	return nil
}

// ---------------------------------------------------------------- world

// world is the tenant's roles and memberships, changed in memory first so
// a plan can be computed (and returned for a dry run) before anything is
// written.
type world struct {
	tx      *store.TenantTx
	now     time.Time
	roles   map[string]*store.BusinessRole
	ents    map[string][]int64
	members map[int64]map[string]*store.RoleMember // identity -> role -> member
	groups  map[int64]*store.Group
	people  map[int64]*store.Identity
	// what a change takes away: identity -> groups some role no longer grants them
	lost map[int64]map[int64]bool
	// identities whose grants to check
	touched map[int64]bool
	// active birthright exclusions: role -> identity (issue #214)
	excluded map[string]map[int64]bool
}

func load(tx *store.TenantTx, now time.Time) (*world, error) {
	w := &world{tx: tx, now: now, roles: map[string]*store.BusinessRole{}, ents: map[string][]int64{},
		members: map[int64]map[string]*store.RoleMember{}, groups: map[int64]*store.Group{},
		people: map[int64]*store.Identity{}, lost: map[int64]map[int64]bool{}, touched: map[int64]bool{},
		excluded: map[string]map[int64]bool{}}
	rs, err := tx.BusinessRoles()
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		w.roles[r.ID] = r
	}
	es, err := tx.AllRoleEntitlements()
	if err != nil {
		return nil, err
	}
	for _, e := range es {
		w.ents[e.RoleID] = append(w.ents[e.RoleID], e.GroupID)
	}
	ms, err := tx.AllRoleMembers()
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		w.member(m)
	}
	xs, err := tx.AllRoleExclusions()
	if err != nil {
		return nil, err
	}
	for _, x := range xs {
		if x.Active() {
			if w.excluded[x.RoleID] == nil {
				w.excluded[x.RoleID] = map[int64]bool{}
			}
			w.excluded[x.RoleID][x.IdentityID] = true
		}
	}
	return w, nil
}

func (w *world) member(m *store.RoleMember) {
	if w.members[m.IdentityID] == nil {
		w.members[m.IdentityID] = map[string]*store.RoleMember{}
	}
	w.members[m.IdentityID][m.RoleID] = m
}

func (w *world) group(id int64) (*store.Group, error) {
	if g, ok := w.groups[id]; ok {
		return g, nil
	}
	g, err := w.tx.Group(id)
	if errors.Is(err, store.ErrNotFound) {
		g, err = nil, nil
	}
	if err == nil {
		w.groups[id] = g
	}
	return g, err
}

func (w *world) identity(id int64) (*store.Identity, error) {
	if i, ok := w.people[id]; ok {
		return i, nil
	}
	i, err := w.tx.Identity(id)
	if errors.Is(err, store.ErrNotFound) {
		i, err = nil, nil
	}
	if err == nil {
		w.people[id] = i
	}
	return i, err
}

func (w *world) role(id string) (*store.BusinessRole, error) {
	if r, ok := w.roles[id]; ok {
		return r, nil
	}
	return nil, refuse(404, "role_not_found", "role not found")
}

func (w *world) lose(identity int64, groups ...int64) {
	if w.lost[identity] == nil {
		w.lost[identity] = map[int64]bool{}
	}
	for _, g := range groups {
		w.lost[identity][g] = true
	}
	w.touched[identity] = true
}

// add assigns a role in memory.
func (w *world) add(roleID string, identity int64, source string, by *string, reqID *string) {
	w.member(&store.RoleMember{RoleID: roleID, IdentityID: identity, Source: source, AssignedBy: by, AssignedAt: w.now, RequestID: reqID})
	w.touched[identity] = true
}

// drop removes a membership in memory.
func (w *world) drop(roleID string, identity int64) {
	delete(w.members[identity], roleID)
	w.lose(identity, w.ents[roleID]...)
}

// wanted is the groups a person's active roles grant, with the roles.
func (w *world) wanted(identity int64) map[int64][]string {
	out := map[int64][]string{}
	for rid := range w.members[identity] {
		if r := w.roles[rid]; r == nil || r.Status != store.RoleActive {
			continue
		}
		for _, g := range w.ents[rid] {
			out[g] = append(out[g], w.roles[rid].Name)
		}
	}
	for g := range out {
		sort.Strings(out[g])
	}
	return out
}

// applyRule brings a role's rule members in step with its rule.
func (w *world) applyRule(roleID string) error {
	r := w.roles[roleID]
	rule, err := ParseRule(r.Birthright)
	if err != nil {
		return err
	}
	matched := map[int64]bool{}
	if rule != nil && r.Status == store.RoleActive {
		people, err := w.tx.Identities()
		if err != nil {
			return err
		}
		var cond *abac.Node
		var shared abac.Attrs
		var resolver *abac.Resolver
		if rule.Policy != "" {
			conds, err := abac.Active(w.tx)
			if err != nil {
				return err
			}
			if resolver, err = abac.NewResolver(w.tx, w.now); err != nil {
				return err
			}
			cond = conds[rule.Policy]
			shared = abac.Merge(abac.ContextAttrs(w.now, 0), abac.RoleAttrs(r))
		}
		for _, p := range people {
			w.people[p.ID] = p
			var attrs abac.Attrs
			if cond != nil {
				attrs = abac.Merge(resolver.Identity(p), shared)
			}
			if rule.Match(p, cond, attrs) && !w.excluded[roleID][p.ID] { // an excluded person is not a rule match
				matched[p.ID] = true
				if _, ok := w.members[p.ID][roleID]; !ok {
					w.add(roleID, p.ID, store.MemberRule, nil, nil)
				}
			}
		}
	}
	for id, ms := range w.members {
		if m, ok := ms[roleID]; ok && m.Source == store.MemberRule && !matched[id] {
			w.drop(roleID, id)
		}
	}
	return nil
}

// ---------------------------------------------------------------- plan

// Step actions.
const (
	AddGrant    = "add_grant"    // grant the group to the account (source "role")
	RemoveGrant = "remove_grant" // delete a role grant no role still justifies
	KeepGrant   = "keep_grant"   // a group the change takes away that stays (granted another way, or by another role)
	NoAccount   = "no_account"   // the person has no account that can receive the group
	AddMember   = "add_member"
	DropMember  = "remove_member"
)

// Step is one change of a plan.
type Step struct {
	Action     string `json:"action"`
	IdentityID int64  `json:"identity_id"`
	Identity   string `json:"identity"`
	RoleID     string `json:"role_id,omitempty"`
	Role       string `json:"role,omitempty"`
	Source     string `json:"source,omitempty"` // member source
	GroupID    int64  `json:"group_id,omitempty"`
	Group      string `json:"group,omitempty"`
	AccountID  *int64 `json:"account_id,omitempty"`
	EdgeID     *int64 `json:"edge_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Plan is what a change does.
type Plan struct {
	DryRun  bool   `json:"dry_run"`
	Steps   []Step `json:"steps"`
	Adds    int    `json:"grants_added"`
	Removes int    `json:"grants_removed"`
	Members int    `json:"members_added"`
	Leaves  int    `json:"members_removed"`
	Missing int    `json:"no_account"`
}

func (p *Plan) add(s Step) {
	switch s.Action {
	case AddGrant:
		p.Adds++
	case RemoveGrant:
		p.Removes++
	case AddMember:
		p.Members++
	case DropMember:
		p.Leaves++
	case NoAccount:
		p.Missing++
	}
	p.Steps = append(p.Steps, s)
}

// plan computes the member and grant steps from the loaded state (before)
// to w (after).
func (w *world) plan(before map[int64]map[string]*store.RoleMember) (*Plan, error) {
	p := &Plan{Steps: []Step{}}
	ids := make([]int64, 0, len(w.touched))
	for id := range w.touched {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		person, err := w.identity(id)
		if err != nil {
			return nil, err
		}
		if person == nil {
			continue
		}
		// membership changes
		for _, rid := range sortedKeys(before[id], w.members[id]) {
			_, was := before[id][rid]
			m, is := w.members[id][rid]
			r := w.roles[rid]
			switch {
			case is && !was:
				p.add(Step{Action: AddMember, IdentityID: id, Identity: person.Name, RoleID: rid, Role: r.Name, Source: m.Source})
			case was && !is:
				p.add(Step{Action: DropMember, IdentityID: id, Identity: person.Name, RoleID: rid, Role: r.Name, Source: before[id][rid].Source})
			}
		}
		if err := w.grantSteps(p, person); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func sortedKeys(a, b map[string]*store.RoleMember) []string {
	var out []string
	for k := range a {
		out = append(out, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (w *world) gname(g *store.Group) string { return g.System + ":" + g.Name }

func (w *world) live(e *store.GrantEdge) bool { return e.ExpiresAt == nil || e.ExpiresAt.After(w.now) }

// grantSteps adds the grant steps for one person: grants their roles need,
// role grants nothing justifies any more, and what a change takes away that
// stays.
func (w *world) grantSteps(p *Plan, person *store.Identity) error {
	want := w.wanted(person.ID)
	accts, err := w.tx.IdentityAccounts(person.ID)
	if err != nil {
		return err
	}
	// the live edges from the person's accounts, by group
	held := map[int64][]*store.GrantEdge{}
	var roleEdges []*store.GrantEdge
	for _, a := range accts {
		es, err := w.tx.EdgesFrom(graph.Key("account", a.ID))
		if err != nil {
			return err
		}
		for _, e := range es {
			kind, gid, err := graph.ParseKey(e.Dst)
			if err != nil || kind != "group" {
				continue
			}
			if e.Source == "role" {
				roleEdges = append(roleEdges, e)
			}
			if a.Status == "active" && w.live(e) {
				held[gid] = append(held[gid], e)
			}
		}
	}
	for _, gid := range sortedGroups(want) {
		if len(held[gid]) > 0 || person.Status != "active" {
			continue
		}
		g, err := w.group(gid)
		if err != nil {
			return err
		}
		if g == nil {
			continue
		}
		s := Step{IdentityID: person.ID, Identity: person.Name, GroupID: gid, Group: w.gname(g),
			Reason: "granted by " + strings.Join(want[gid], ", ")}
		acct, err := jit.AccountFor(w.tx, person.ID, g)
		var je *jit.Error
		if errors.As(err, &je) {
			s.Action, s.Reason = NoAccount, "no active account in "+g.System+" can receive it"
		} else if err != nil {
			return err
		} else {
			s.Action, s.AccountID = AddGrant, &acct.ID
		}
		p.add(s)
	}
	removed := map[int64]bool{}
	for _, e := range roleEdges {
		_, gid, _ := graph.ParseKey(e.Dst)
		if _, ok := want[gid]; ok && person.Status == "active" {
			continue
		}
		g, err := w.group(gid)
		if err != nil {
			return err
		}
		name := e.Dst
		if g != nil {
			name = w.gname(g)
		}
		id := e.ID
		reason := "no role of theirs grants it any more"
		if person.Status != "active" {
			reason = "the person is " + person.Status
		}
		p.add(Step{Action: RemoveGrant, IdentityID: person.ID, Identity: person.Name, GroupID: gid, Group: name, EdgeID: &id, Reason: reason})
		removed[gid] = true
	}
	for _, gid := range sortedSet(w.lost[person.ID]) {
		if removed[gid] {
			continue
		}
		g, err := w.group(gid)
		if err != nil || g == nil {
			return err
		}
		var reason string
		switch {
		case len(want[gid]) > 0:
			reason = "still granted by " + strings.Join(want[gid], ", ")
		case len(held[gid]) > 0:
			var srcs []string
			for _, e := range held[gid] {
				if e.Source != "role" && !slices.Contains(srcs, e.Source) {
					srcs = append(srcs, e.Source)
				}
			}
			if len(srcs) == 0 {
				continue
			}
			reason = "granted outside roles (" + strings.Join(srcs, ", ") + "); review it separately"
		default:
			continue // not held: nothing to remove
		}
		p.add(Step{Action: KeepGrant, IdentityID: person.ID, Identity: person.Name, GroupID: gid, Group: w.gname(g), Reason: reason})
	}
	return nil
}

func sortedGroups(m map[int64][]string) []int64 {
	out := make([]int64, 0, len(m))
	for g := range m {
		out = append(out, g)
	}
	slices.Sort(out)
	return out
}

func sortedSet(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for g := range m {
		out = append(out, g)
	}
	slices.Sort(out)
	return out
}

// execute applies the plan's grant steps.
func (w *world) execute(p *Plan) error {
	for _, s := range p.Steps {
		switch s.Action {
		case AddGrant:
			src, dst := graph.Key("account", *s.AccountID), graph.Key("group", s.GroupID)
			if old, err := w.tx.EdgeBetween(src, dst); err == nil { // an expired or inactive-account grant: replace it
				if err := w.tx.DeleteEdge(old.ID); err != nil {
					return err
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
			if _, err := w.tx.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "role",
				CreatedAt: w.now}); err != nil {
				return err
			}
		case RemoveGrant:
			if err := w.tx.DeleteRoleEdge(*s.EdgeID); err != nil {
				return err
			}
		}
	}
	return nil
}

// persistMembers writes the membership changes from before to w.
func (w *world) persistMembers(before map[int64]map[string]*store.RoleMember) error {
	for id := range w.touched {
		for _, rid := range sortedKeys(before[id], w.members[id]) {
			_, was := before[id][rid]
			m, is := w.members[id][rid]
			switch {
			case is && !was:
				if err := w.tx.AddRoleMember(m); err != nil {
					return err
				}
			case was && !is:
				if err := w.tx.DeleteRoleMember(rid, id); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func snapshotMembers(w *world) map[int64]map[string]*store.RoleMember {
	out := make(map[int64]map[string]*store.RoleMember, len(w.members))
	for id, ms := range w.members {
		c := make(map[string]*store.RoleMember, len(ms))
		for k, v := range ms {
			c[k] = v
		}
		out[id] = c
	}
	return out
}

func planDetail(p *Plan) ojson.Object {
	steps := make([]ojson.Object, 0, len(p.Steps))
	for _, s := range p.Steps {
		o := ojson.Object{{Key: "action", Value: s.Action}, {Key: "identity_id", Value: s.IdentityID}}
		if s.RoleID != "" {
			o = append(o, ojson.KV{Key: "role_id", Value: s.RoleID})
		}
		if s.GroupID != 0 {
			o = append(o, ojson.KV{Key: "group_id", Value: s.GroupID})
		}
		if s.EdgeID != nil {
			o = append(o, ojson.KV{Key: "edge_id", Value: *s.EdgeID})
		}
		steps = append(steps, o)
	}
	return ojson.Object{{Key: "grants_added", Value: p.Adds}, {Key: "grants_removed", Value: p.Removes},
		{Key: "members_added", Value: p.Members}, {Key: "members_removed", Value: p.Leaves},
		{Key: "no_account", Value: p.Missing}, {Key: "steps", Value: steps}}
}

// ---------------------------------------------------------------- changes

// Result is a role after a change (saved, or as it would be for a dry
// run), with its entitlements and the change's plan.
type Result struct {
	Role         *store.BusinessRole
	Entitlements []int64
	Plan         *Plan
}

func (w *world) result(r *store.BusinessRole, p *Plan) *Result {
	return &Result{Role: r, Entitlements: w.ents[r.ID], Plan: p}
}

func uidp(by Actor) *string {
	if by.UserID == uuid.Nil {
		return nil
	}
	s := by.UserID.String()
	return &s
}

// Snapshot is a version's JSON: the role and its entitlements.
func Snapshot(r *store.BusinessRole, ents []int64) (string, error) {
	var rule any
	if r.Birthright != nil {
		rule = json.RawMessage(*r.Birthright)
	}
	b, err := json.Marshal(map[string]any{"name": r.Name, "description": r.Description, "owner_identity_id": r.OwnerIdentityID,
		"risk": r.Risk, "requestable": r.Requestable, "birthright": rule, "status": r.Status, "entitlements": ents})
	return string(b), err
}

func (w *world) version(r *store.BusinessRole, note string, by Actor) error {
	snap, err := Snapshot(r, w.ents[r.ID])
	if err != nil {
		return err
	}
	var n *string
	if note != "" {
		n = &note
	}
	return w.tx.AddRoleVersion(&store.RoleVersion{RoleID: r.ID, Version: r.Version, Snapshot: snap, Note: n,
		ChangedBy: uidp(by), Actor: by.Display, ChangedAt: w.now})
}

func roleDetail(r *store.BusinessRole, p *Plan) ojson.Object {
	d := ojson.Object{{Key: "role_id", Value: r.ID}, {Key: "name", Value: r.Name}, {Key: "version", Value: r.Version}}
	return append(d, planDetail(p)...)
}

// Create saves a new role, assigns its rule members and grants their
// entitlements.
func Create(tx *store.TenantTx, s Spec, by Actor, dryRun bool, now time.Time) (*Result, error) {
	w, err := load(tx, now)
	if err != nil {
		return nil, err
	}
	if err := w.validate(&s, ""); err != nil {
		return nil, err
	}
	rule, err := ruleJSON(s.Birthright)
	if err != nil {
		return nil, err
	}
	r := &store.BusinessRole{ID: uuid.NewString(), Name: s.Name, Description: s.Description, OwnerIdentityID: s.OwnerIdentityID,
		Risk: s.Risk, Requestable: s.Requestable, Birthright: rule, Status: store.RoleActive, Version: 1, CreatedAt: now,
		UpdatedBy: uidp(by), UpdatedAt: now}
	w.roles[r.ID], w.ents[r.ID] = r, s.Entitlements
	before := snapshotMembers(w)
	if err := w.applyRule(r.ID); err != nil {
		return nil, err
	}
	p, err := w.plan(before)
	if err != nil {
		return nil, err
	}
	p.DryRun = dryRun
	if dryRun {
		return w.result(r, p), nil
	}
	if err := tx.InsertBusinessRole(r); err != nil {
		return nil, err
	}
	if err := tx.SetRoleEntitlements(r.ID, s.Entitlements); err != nil {
		return nil, err
	}
	if err := w.finish(before, p); err != nil {
		return nil, err
	}
	if err := w.version(r, s.Note, by); err != nil {
		return nil, err
	}
	return w.result(r, p), tx.Audit(now, by.Display, "role.create", roleDetail(r, p))
}

func (w *world) finish(before map[int64]map[string]*store.RoleMember, p *Plan) error {
	if err := w.persistMembers(before); err != nil {
		return err
	}
	return w.execute(p)
}

func (w *world) active(id string) (*store.BusinessRole, error) {
	r, err := w.role(id)
	if err != nil {
		return nil, err
	}
	if r.Status != store.RoleActive {
		return nil, refuse(409, "role_retired", "%s is retired", r.Name)
	}
	return r, nil
}

// Update saves a role's new content (version must be its current version),
// brings its rule members in step and its members' grants in line with the
// new entitlements.
func Update(tx *store.TenantTx, id string, version int, s Spec, by Actor, dryRun bool, now time.Time) (*Result, error) {
	w, err := load(tx, now)
	if err != nil {
		return nil, err
	}
	old, err := w.active(id)
	if err != nil {
		return nil, err
	}
	if version != old.Version {
		return nil, refuse(409, "version_conflict", "the role changed since version %d (now %d); reload it", version, old.Version)
	}
	if err := w.validate(&s, id); err != nil {
		return nil, err
	}
	rule, err := ruleJSON(s.Birthright)
	if err != nil {
		return nil, err
	}
	r := *old
	r.Name, r.Description, r.OwnerIdentityID, r.Risk, r.Requestable, r.Birthright = s.Name, s.Description, s.OwnerIdentityID, s.Risk, s.Requestable, rule
	r.Version, r.UpdatedBy, r.UpdatedAt = old.Version+1, uidp(by), now
	gone := without(w.ents[id], s.Entitlements)
	before := snapshotMembers(w)
	w.roles[id], w.ents[id] = &r, s.Entitlements
	for pid, ms := range w.members {
		if _, ok := ms[id]; ok {
			w.lose(pid, gone...)
		}
	}
	if err := w.applyRule(id); err != nil {
		return nil, err
	}
	p, err := w.plan(before)
	if err != nil {
		return nil, err
	}
	p.DryRun = dryRun
	if dryRun {
		return w.result(&r, p), nil
	}
	if err := tx.SaveBusinessRole(&r, old.Version); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the role changed; reload it")
	} else if err != nil {
		return nil, err
	}
	if err := tx.SetRoleEntitlements(id, s.Entitlements); err != nil {
		return nil, err
	}
	if err := w.finish(before, p); err != nil {
		return nil, err
	}
	if err := w.version(&r, s.Note, by); err != nil {
		return nil, err
	}
	return w.result(&r, p), tx.Audit(now, by.Display, "role.update", roleDetail(&r, p))
}

func without(a, b []int64) []int64 {
	var out []int64
	for _, g := range a {
		if !slices.Contains(b, g) {
			out = append(out, g)
		}
	}
	return out
}

// Retire ends a role: every member loses it (and the grants only it
// justified), pending requests for it are denied, and it can no longer be
// assigned or requested. A reason is required.
func Retire(tx *store.TenantTx, id, reason string, by Actor, dryRun bool, now time.Time) (*Result, error) {
	rp, err := reasonPtr(reason, true)
	if err != nil {
		return nil, err
	}
	w, err := load(tx, now)
	if err != nil {
		return nil, err
	}
	old, err := w.active(id)
	if err != nil {
		return nil, err
	}
	r := *old
	r.Status, r.Requestable, r.Version, r.UpdatedBy, r.UpdatedAt = store.RoleRetired, false, old.Version+1, uidp(by), now
	before := snapshotMembers(w)
	w.roles[id] = &r
	for pid, ms := range w.members {
		if _, ok := ms[id]; ok {
			w.drop(id, pid)
		}
	}
	p, err := w.plan(before)
	if err != nil {
		return nil, err
	}
	p.DryRun = dryRun
	if dryRun {
		return w.result(&r, p), nil
	}
	if err := tx.SaveBusinessRole(&r, old.Version); err != nil {
		return nil, err
	}
	if err := w.finish(before, p); err != nil {
		return nil, err
	}
	pend, err := tx.RoleRequests(store.RoleRequestFilter{Status: store.RequestPending, RoleID: id})
	if err != nil {
		return nil, err
	}
	note := "the role was retired"
	for _, q := range pend {
		q.Status, q.DecidedBy, q.DecidedAt, q.DecisionReason = store.RequestDenied, uidp(by), &now, &note
		if err := tx.SaveRoleRequest(q, store.RequestPending); err != nil {
			return nil, err
		}
	}
	if err := w.version(&r, *rp, by); err != nil {
		return nil, err
	}
	d := append(roleDetail(&r, p), ojson.KV{Key: "reason", Value: *rp}, ojson.KV{Key: "requests_denied", Value: len(pend)})
	return w.result(&r, p), tx.Audit(now, by.Display, "role.retire", d)
}

func reasonPtr(reason string, required bool) (*string, error) {
	r := strings.TrimSpace(reason)
	if len(r) > MaxReason || (required && r == "") {
		return nil, refuse(422, "reason_required", "a reason of 1 to %d characters is required", MaxReason)
	}
	if r == "" {
		return nil, nil
	}
	return &r, nil
}

// Assign gives a role to an active person by hand.
func Assign(tx *store.TenantTx, id string, identityID int64, reason string, by Actor, dryRun bool, now time.Time) (*Result, error) {
	rp, err := reasonPtr(reason, false)
	if err != nil {
		return nil, err
	}
	return assign(tx, id, identityID, store.MemberManual, nil, rp, by, dryRun, now)
}

func assign(tx *store.TenantTx, id string, identityID int64, source string, reqID, reason *string, by Actor, dryRun bool,
	now time.Time) (*Result, error) {
	w, err := load(tx, now)
	if err != nil {
		return nil, err
	}
	r, err := w.active(id)
	if err != nil {
		return nil, err
	}
	person, err := w.identity(identityID)
	if err != nil {
		return nil, err
	}
	switch {
	case person == nil:
		return nil, refuse(404, "identity_not_found", "person not found")
	case person.Status != "active":
		return nil, refuse(409, "identity_not_active", "%s is not active", person.Name)
	}
	if _, ok := w.members[identityID][id]; ok {
		return nil, refuse(409, "already_member", "%s already holds %s", person.Name, r.Name)
	}
	before := snapshotMembers(w)
	w.add(id, identityID, source, uidp(by), reqID)
	p, err := w.plan(before)
	if err != nil {
		return nil, err
	}
	p.DryRun = dryRun
	if dryRun {
		return w.result(r, p), nil
	}
	if err := w.finish(before, p); err != nil {
		return nil, err
	}
	d := append(roleDetail(r, p), ojson.KV{Key: "identity_id", Value: identityID}, ojson.KV{Key: "source", Value: source})
	if reqID != nil {
		d = append(d, ojson.KV{Key: "request_id", Value: *reqID})
	}
	if reason != nil {
		d = append(d, ojson.KV{Key: "reason", Value: *reason})
	}
	return w.result(r, p), tx.Audit(now, by.Display, "role.assign", d)
}

// Unassign takes a role away from a person, with the grants only it
// justified. A rule member is removed by changing the rule instead.
func Unassign(tx *store.TenantTx, id string, identityID int64, reason string, by Actor, dryRun bool, now time.Time) (*Result, error) {
	rp, err := reasonPtr(reason, true)
	if err != nil {
		return nil, err
	}
	w, err := load(tx, now)
	if err != nil {
		return nil, err
	}
	r, err := w.role(id)
	if err != nil {
		return nil, err
	}
	m, ok := w.members[identityID][id]
	if !ok {
		return nil, refuse(404, "not_member", "the person does not hold this role")
	}
	if m.Source == store.MemberRule && r.Status == store.RoleActive {
		return nil, refuse(409, "assigned_by_rule", "the birthright rule assigns this role; change the rule to remove it")
	}
	before := snapshotMembers(w)
	w.drop(id, identityID)
	p, err := w.plan(before)
	if err != nil {
		return nil, err
	}
	p.DryRun = dryRun
	if dryRun {
		return w.result(r, p), nil
	}
	if err := w.finish(before, p); err != nil {
		return nil, err
	}
	d := append(roleDetail(r, p), ojson.KV{Key: "identity_id", Value: identityID}, ojson.KV{Key: "reason", Value: *rp})
	return w.result(r, p), tx.Audit(now, by.Display, "role.unassign", d)
}

// Reconcile brings a role in step: rule members with the rule (after HR
// changes), and every member's grants (after a grant was removed elsewhere
// or an account appeared). A dry run shows what would change.
func Reconcile(tx *store.TenantTx, id string, by Actor, dryRun bool, now time.Time) (*Result, error) {
	w, err := load(tx, now)
	if err != nil {
		return nil, err
	}
	r, err := w.active(id)
	if err != nil {
		return nil, err
	}
	before := snapshotMembers(w)
	for pid, ms := range w.members {
		if _, ok := ms[id]; ok {
			w.touched[pid] = true
		}
	}
	if err := w.applyRule(id); err != nil {
		return nil, err
	}
	p, err := w.plan(before)
	if err != nil {
		return nil, err
	}
	p.DryRun = dryRun
	if dryRun || len(p.Steps) == 0 {
		return w.result(r, p), nil
	}
	if err := w.finish(before, p); err != nil {
		return nil, err
	}
	return w.result(r, p), tx.Audit(now, by.Display, "role.reconcile", roleDetail(r, p))
}

// ---------------------------------------------------------------- drift

// Gap is a member missing some of the role's entitlements.
type Gap struct {
	IdentityID int64
	Missing    []int64 // groups
}

// Holder is someone who holds role entitlements without the role.
type Holder struct {
	IdentityID int64
	Held       []int64 // groups
}

// Drift is a role's drift: members missing entitlements, and people who
// hold at least half of its entitlements (all, for a one-group role)
// without it.
type Drift struct {
	Entitlements []int64
	Missing      []Gap
	Holders      []Holder
}

// RoleDrift computes a role's drift at now.
func RoleDrift(tx *store.TenantTx, id string, now time.Time) (*Drift, error) {
	w, err := load(tx, now)
	if err != nil {
		return nil, err
	}
	if _, err := w.role(id); err != nil {
		return nil, err
	}
	ents := w.ents[id]
	d := &Drift{Entitlements: ents, Missing: []Gap{}, Holders: []Holder{}}
	// who holds each group, through an active account and a live grant
	acctOwner := map[int64]*int64{}
	accts, err := tx.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if a.Status == "active" {
			acctOwner[a.ID] = a.IdentityID
		}
	}
	holds := map[int64]map[int64]bool{} // identity -> groups
	for _, g := range ents {
		es, err := tx.EdgesTo(graph.Key("group", g))
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			kind, aid, err := graph.ParseKey(e.Src)
			if err != nil || kind != "account" || !w.live(e) {
				continue
			}
			owner := acctOwner[aid]
			if owner == nil {
				continue
			}
			if holds[*owner] == nil {
				holds[*owner] = map[int64]bool{}
			}
			holds[*owner][g] = true
		}
	}
	members, err := tx.RoleMembers(id)
	if err != nil {
		return nil, err
	}
	isMember := map[int64]bool{}
	for _, m := range members {
		isMember[m.IdentityID] = true
		var miss []int64
		for _, g := range ents {
			if !holds[m.IdentityID][g] {
				miss = append(miss, g)
			}
		}
		if len(miss) > 0 {
			d.Missing = append(d.Missing, Gap{m.IdentityID, miss})
		}
	}
	need := (len(ents) + 1) / 2
	for pid, gs := range holds {
		if isMember[pid] || w.excluded[id][pid] || len(gs) < need || len(gs) == 0 {
			continue
		}
		p, err := w.identity(pid)
		if err != nil {
			return nil, err
		}
		if p == nil || p.Status != "active" {
			continue
		}
		d.Holders = append(d.Holders, Holder{pid, sortedSet(gs)})
	}
	sort.Slice(d.Holders, func(i, j int) bool {
		if a, b := len(d.Holders[i].Held), len(d.Holders[j].Held); a != b {
			return a > b
		}
		return d.Holders[i].IdentityID < d.Holders[j].IdentityID
	})
	return d, nil
}

// ---------------------------------------------------------------- requests

// Request files a pending request for a requestable role. forOthers allows
// beneficiaries other than the actor's own identity.
func Request(tx *store.TenantTx, id string, beneficiary int64, justification string, by Actor, forOthers bool, now time.Time) (*store.RoleRequest, error) {
	just := strings.TrimSpace(justification)
	if just == "" || len(just) > MaxJustify {
		return nil, refuse(422, "justification_required", "a justification of 1 to %d characters is required", MaxJustify)
	}
	r, err := tx.BusinessRole(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "role_not_found", "role not found")
	} else if err != nil {
		return nil, err
	}
	switch {
	case r.Status != store.RoleActive || !r.Requestable:
		return nil, refuse(409, "not_requestable", "%s cannot be requested", r.Name)
	case (by.IdentityID == nil || *by.IdentityID != beneficiary) && !forOthers:
		return nil, refuse(403, "for_others_not_allowed", "you can request access only for yourself")
	}
	ben, err := tx.Identity(beneficiary)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "beneficiary_not_found", "person not found")
	} else if err != nil {
		return nil, err
	}
	if ben.Status != "active" {
		return nil, refuse(409, "beneficiary_not_active", "%s is not active", ben.Name)
	}
	ms, err := tx.IdentityRoles(beneficiary)
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		if m.RoleID == id {
			return nil, refuse(409, "already_member", "%s already holds %s", ben.Name, r.Name)
		}
	}
	if open, err := tx.RoleRequests(store.RoleRequestFilter{Status: store.RequestPending, RoleID: id, InvolvingIdentity: beneficiary}); err != nil {
		return nil, err
	} else {
		for _, q := range open {
			if q.BeneficiaryID == beneficiary {
				return nil, refuse(409, "already_requested", "%s already has an open request for %s", ben.Name, r.Name)
			}
		}
	}
	q := &store.RoleRequest{ID: uuid.NewString(), RoleID: id, BeneficiaryID: beneficiary, RequestedBy: by.UserID.String(),
		Justification: just, Status: store.RequestPending, RequestedAt: now}
	if err := tx.InsertRoleRequest(q); err != nil {
		return nil, err
	}
	return q, tx.Audit(now, by.Display, "role.request.submit", reqDetail(q, nil))
}

func reqDetail(q *store.RoleRequest, reason *string) ojson.Object {
	d := ojson.Object{{Key: "role_request_id", Value: q.ID}, {Key: "role_id", Value: q.RoleID},
		{Key: "beneficiary_id", Value: q.BeneficiaryID}, {Key: "status", Value: q.Status}}
	if reason != nil {
		d = append(d, ojson.KV{Key: "reason", Value: *reason})
	}
	return d
}

func pending(tx *store.TenantTx, id string) (*store.RoleRequest, error) {
	q, err := tx.RoleRequest(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "request_not_found", "request not found")
	} else if err != nil {
		return nil, err
	}
	if q.Status != store.RequestPending {
		return nil, refuse(409, "not_pending", "the request is %s", q.Status)
	}
	return q, nil
}

// Approve assigns the role of a pending request. Nobody approves a request
// they made or that gives them the role.
func Approve(tx *store.TenantTx, id, reason string, by Actor, now time.Time) (*store.RoleRequest, *Result, error) {
	q, err := pending(tx, id)
	if err != nil {
		return nil, nil, err
	}
	rp, err := reasonPtr(reason, false)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case q.RequestedBy == by.UserID.String():
		return nil, nil, refuse(403, "self_approval", "you cannot approve a request you made")
	case by.IdentityID != nil && *by.IdentityID == q.BeneficiaryID:
		return nil, nil, refuse(403, "self_approval", "you cannot approve access for yourself")
	}
	res, err := assign(tx, q.RoleID, q.BeneficiaryID, store.MemberRequest, &q.ID, rp, by, false, now)
	if err != nil {
		return nil, nil, err
	}
	q.Status, q.DecidedBy, q.DecidedAt, q.DecisionReason = store.RequestApproved, uidp(by), &now, rp
	if err := tx.SaveRoleRequest(q, store.RequestPending); err != nil {
		return nil, nil, err
	}
	return q, res, tx.Audit(now, by.Display, "role.request.approve", reqDetail(q, rp))
}

// Deny rejects a pending request; a reason is required.
func Deny(tx *store.TenantTx, id, reason string, by Actor, now time.Time) (*store.RoleRequest, error) {
	q, err := pending(tx, id)
	if err != nil {
		return nil, err
	}
	rp, err := reasonPtr(reason, true)
	if err != nil {
		return nil, err
	}
	q.Status, q.DecidedBy, q.DecidedAt, q.DecisionReason = store.RequestDenied, uidp(by), &now, rp
	if err := tx.SaveRoleRequest(q, store.RequestPending); err != nil {
		return nil, err
	}
	return q, tx.Audit(now, by.Display, "role.request.deny", reqDetail(q, rp))
}

// Cancel withdraws a pending request; only its requester may (others' look
// missing).
func Cancel(tx *store.TenantTx, id string, by Actor, now time.Time) (*store.RoleRequest, error) {
	q, err := tx.RoleRequest(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && q.RequestedBy != by.UserID.String()) {
		return nil, refuse(404, "request_not_found", "request not found")
	} else if err != nil {
		return nil, err
	}
	if q.Status != store.RequestPending {
		return nil, refuse(409, "not_pending", "the request is %s", q.Status)
	}
	q.Status, q.DecidedAt = store.RequestCancelled, &now
	if err := tx.SaveRoleRequest(q, store.RequestPending); err != nil {
		return nil, err
	}
	return q, tx.Audit(now, by.Display, "role.request.cancel", reqDetail(q, nil))
}
