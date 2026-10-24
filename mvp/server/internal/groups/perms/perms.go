// Package perms is the role and permission layer of native groups (issue #62,
// GR-19; design docs/design/groups-grouper-parity.md §10.10).
//
// Storage is the attribute framework of GR-7 (internal/groups/attrs): a
// permission resource is a name of a definition of type perm, an action is one
// of that definition's actions, and a permission assignment sits on a role (a
// group) or on a role's membership (the (role, identity) pair). Resource and
// action inheritance are the implication closures of the definition. A limit is
// an assignment of a definition of type limit on a permission assignment. This
// package reads that data (it writes none, except Import, which goes through
// attrs.Assign) and adds:
//
//   - perms.go: loading the assignments, the allow/disallow heuristics (Decide)
//     and the effective permissions of an identity (Effective).
//   - limits.go: limits compiled to Cedar `context` conditions, and their evaluation.
//   - policy.go: the permission assignments as Cedar policy text.
//   - pitview.go: the same decisions as of an instant, from the PIT tables.
//   - grouper.go: the Grouper-shaped permission document (export and import).
//
// Every read goes through *store.TenantTx, so it is scoped to the request's tenant.
package perms

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Source ranks how an assignment reaches the subject: the (role, identity)
// pair is the most direct, then a role the identity is a direct member of, then
// a role it reaches through nesting.
const (
	SrcNested = iota
	SrcDirect
	SrcSubject
)

// Limit is a limit on a permission assignment: the limit name's full name and
// its values as text.
type Limit struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// Assignment is one permission assignment.
type Assignment struct {
	ID       string
	DefID    string
	NameID   string
	ActionID string
	// Resource is the permission resource's full name, Action the action's name.
	Resource string
	Action   string
	Role     store.GroupID
	RoleName string
	// Subject is set on a (role, identity) assignment.
	Subject     *int64
	Disallowed  bool
	EnabledFrom *time.Time
	DisabledAt  *time.Time
	Limits      []Limit
}

// InDates reports whether the assignment's dates include now.
func (a *Assignment) InDates(now time.Time) bool {
	return (a.EnabledFrom == nil || !now.Before(*a.EnabledFrom)) && (a.DisabledAt == nil || now.Before(*a.DisabledAt))
}

// Error is a refused request: Kind says how the API answers.
type Error struct {
	Kind int // 404, 422
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func notFound(what string) error { return &Error{404, "not_found", "no such " + what} }

func invalid(code, format string, args ...any) error {
	return &Error{422, code, fmt.Sprintf(format, args...)}
}

// closures are the implication closures of one definition: name (or action) id
// to the ids it implies.
type closures struct {
	names, actions map[string]map[string]bool
}

// Set is the permission assignments of the tenant, with what it takes to
// resolve and compare them. Build it with Load (now) or LoadAt (an instant of
// the past); it is valid for the transaction it was loaded in.
type Set struct {
	Assignments []*Assignment
	tx          *store.TenantTx
	byDef       map[string]*closures
	nameFull    map[string]string // name id -> full name
	actionName  map[string]string // action id -> name
}

func newSet(tx *store.TenantTx) *Set {
	return &Set{tx: tx, byDef: map[string]*closures{}, nameFull: map[string]string{}, actionName: map[string]string{}}
}

func (s *Set) closure(def string) (*closures, error) {
	if c, ok := s.byDef[def]; ok {
		return c, nil
	}
	c := &closures{names: map[string]map[string]bool{}, actions: map[string]map[string]bool{}}
	for kind, m := range map[string]map[string]map[string]bool{store.ImpliesNames: c.names, store.ImpliesActions: c.actions} {
		rows, err := s.tx.GrpAttrImpliesOfDef(kind, def)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if m[r.From] == nil {
				m[r.From] = map[string]bool{}
			}
			m[r.From][r.To] = true
		}
	}
	s.byDef[def] = c
	return c, nil
}

// fullName returns the full name of a name id (cached).
func (s *Set) fullName(nameID string) (string, error) {
	if f, ok := s.nameFull[nameID]; ok {
		return f, nil
	}
	n, err := attrs.Name(s.tx, nameID)
	if err != nil {
		return "", err
	}
	d, err := attrs.Def(s.tx, n.DefID)
	if err != nil {
		return "", err
	}
	f := attrs.NameFullName(d, n)
	s.nameFull[nameID] = f
	return f, nil
}

func (s *Set) actionNameOf(id string) (string, error) {
	if f, ok := s.actionName[id]; ok {
		return f, nil
	}
	a, err := attrs.Action(s.tx, id)
	if err != nil {
		return "", err
	}
	s.actionName[id] = a.Name
	return a.Name, nil
}

// activeGroup loads a role, reporting false for one that is deleted or disabled
// (it grants nothing).
func activeGroup(tx *store.TenantTx, id store.GroupID) (*store.NativeGroup, bool, error) {
	g, err := tx.GrpGroup(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return g, g.Status == "active", nil
}

// Load reads every permission assignment of the tenant with its limits. It does
// not filter by date: Decide does, for the instant it is asked about.
func Load(tx *store.TenantTx) (*Set, error) {
	rows, err := tx.GrpPermAssigns()
	if err != nil {
		return nil, err
	}
	limits, err := loadLimits(tx)
	if err != nil {
		return nil, err
	}
	s := newSet(tx)
	for _, a := range rows {
		role, subject, ok, err := ownerRole(tx, a.OwnerType, a.OwnerID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		as, err := s.assignment(a.ID, a.DefID, a.NameID, a.ActionID, a.Disallowed, a.EnabledFrom, a.DisabledAt, role, subject, limits[a.ID])
		if err != nil {
			return nil, err
		}
		s.Assignments = append(s.Assignments, as)
	}
	return s, nil
}

// ownerRole resolves the owner of a permission assignment to its role (and the
// identity of a (role, identity) pair). ok is false when the owner is gone,
// disabled, or a membership of a group (not of an identity).
func ownerRole(tx *store.TenantTx, ownerType, ownerID string) (role *store.NativeGroup, subject *int64, ok bool, err error) {
	var gid store.GroupID
	switch ownerType {
	case store.AttrOwnerGroup:
		gid = store.GroupID(ownerID)
	case store.AttrOwnerMembership:
		m, err := tx.GrpDirectMembership(ownerID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, false, nil
		}
		if err != nil {
			return nil, nil, false, err
		}
		if m.MemberIdentity == nil {
			return nil, nil, false, nil
		}
		gid, subject = m.GroupID, m.MemberIdentity
	default:
		return nil, nil, false, nil
	}
	g, active, err := activeGroup(tx, gid)
	if err != nil || !active {
		return nil, nil, false, err
	}
	return g, subject, true, nil
}

func (s *Set) assignment(id, def, name, action string, disallowed bool, from, to *time.Time, role *store.NativeGroup,
	subject *int64, limits []Limit) (*Assignment, error) {
	res, err := s.fullName(name)
	if err != nil {
		return nil, err
	}
	act, err := s.actionNameOf(action)
	if err != nil {
		return nil, err
	}
	return &Assignment{ID: id, DefID: def, NameID: name, ActionID: action, Resource: res, Action: act, Role: role.ID,
		RoleName: role.Name, Subject: subject, Disallowed: disallowed, EnabledFrom: from, DisabledAt: to, Limits: limits}, nil
}

// loadLimits reads the limits of every permission assignment, by assignment id.
func loadLimits(tx *store.TenantTx) (map[string][]Limit, error) {
	ls, err := tx.GrpLimitAssigns()
	if err != nil {
		return nil, err
	}
	vals, err := tx.GrpLimitValues()
	if err != nil {
		return nil, err
	}
	byAssign := map[string][]string{}
	for _, v := range vals {
		byAssign[v.AssignID] = append(byAssign[v.AssignID], keyText(v.Key))
	}
	out := map[string][]Limit{}
	for _, l := range ls {
		n, err := attrs.Name(tx, l.NameID)
		if err != nil {
			return nil, err
		}
		d, err := attrs.Def(tx, n.DefID)
		if err != nil {
			return nil, err
		}
		out[l.OwnerID] = append(out[l.OwnerID], Limit{Name: attrs.NameFullName(d, n), Values: byAssign[l.ID]})
	}
	return out, nil
}

// KeyText is the text of a canonical value key.
func KeyText(key string) string { return keyText(key) }

// keyText is the value of a canonical value key ("s:text", "i:42").
func keyText(key string) string {
	if len(key) >= 2 && key[1] == ':' {
		return key[2:]
	}
	return key
}

// ---------------------------------------------------------------- the heuristics

// Subject is who a decision is for: the identity, the roles it is effectively
// in and, among them, those it is a direct member of.
type Subject struct {
	Identity int64
	Roles    map[store.GroupID]bool
	Direct   map[store.GroupID]bool
}

// SubjectOf reads an identity's roles at now.
func SubjectOf(tx *store.TenantTx, identity int64, now time.Time) (Subject, error) {
	list := store.MembersListID(tx.Tenant())
	roles, err := tx.GrpEffectiveGroupsOf(identity, list)
	if err != nil {
		return Subject{}, err
	}
	sub := Subject{Identity: identity, Roles: map[store.GroupID]bool{}, Direct: map[store.GroupID]bool{}}
	for _, r := range roles {
		sub.Roles[r] = true
	}
	directs, err := tx.GrpDirectsOfIdentity(identity, list)
	if err != nil {
		return Subject{}, err
	}
	for _, m := range directs {
		if (m.EnabledFrom == nil || !now.Before(*m.EnabledFrom)) && (m.DisabledAt == nil || now.Before(*m.DisabledAt)) {
			sub.Direct[m.GroupID] = true
		}
	}
	return sub, nil
}

// Query names what a decision is about, resolved to ids.
type Query struct {
	DefID, NameID, ActionID string
	Resource, Action        string
}

// Resolve finds a permission resource by its full name ("folder:definition:name")
// and one of its definition's actions by name (empty is "assign").
func (s *Set) Resolve(resource, action string) (Query, error) {
	n, err := attrs.NameByFullName(s.tx, resource)
	if err != nil {
		return Query{}, notFound("permission resource")
	}
	d, err := attrs.Def(s.tx, n.DefID)
	if err != nil {
		return Query{}, err
	}
	if d.AttrType != store.AttrTypePerm {
		return Query{}, invalid("not_a_permission", "%q is not a permission resource (its definition is of type %s)", resource, d.AttrType)
	}
	if action == "" {
		action = attrs.DefaultAction
	}
	a, err := s.tx.GrpAttrActionByName(d.ID, action)
	if errors.Is(err, store.ErrNotFound) {
		return Query{}, notFound("permission action")
	}
	if err != nil {
		return Query{}, err
	}
	return Query{DefID: d.ID, NameID: n.ID, ActionID: a.ID, Resource: attrs.NameFullName(d, n), Action: a.Name}, nil
}

type rank struct{ res, act, src int }

func (a rank) better(b rank) bool {
	switch {
	case a.res != b.res:
		return a.res > b.res
	case a.act != b.act:
		return a.act > b.act
	}
	return a.src > b.src
}

// Decision is the answer of the heuristics for one (resource, action).
type Decision struct {
	Allowed bool `json:"allowed"`
	// Reason is allowed, disallowed (a disallow won) or no_permission.
	Reason string `json:"reason"`
	// Via are the assignments at the winning rank.
	Via []*Assignment `json:"-"`
	// Conditional is set, when the decision was made without a context, on an
	// allow whose every winning allow has limits, and on a deny whose every
	// winning disallow has limits (it holds unless a limit is evaluated and fails,
	// and when a context value is missing).
	Conditional bool `json:"conditional,omitempty"`
	// LimitsFailed lists assignments that applied but were set aside because a
	// limit did not hold for the context.
	LimitsFailed []string `json:"limits_failed,omitempty"`
	// ContextMissing lists the context keys that a disallow's limit needed and the
	// caller did not supply (or supplied malformed): the disallow held for them.
	ContextMissing []string `json:"context_missing,omitempty"`
}

// Decide applies the heuristics (design §10.10): of the assignments that reach
// the subject and cover the resource and action, in their dates and, when ctx is
// not nil, with every limit holding, the one that is more specific wins: first by
// resource (the named resource over one that only implies it), then by action,
// then by how directly it reaches the subject ((role, identity) over a direct
// role over a nested role). Among equals a disallow beats an allow. With no
// assignment the answer is no.
// [Grouper's PermissionHeuristics is to be confirmed against its source on import (GR-15).]
func (s *Set) Decide(sub Subject, q Query, ctx Context, now time.Time) (*Decision, error) {
	cl, err := s.closure(q.DefID)
	if err != nil {
		return nil, err
	}
	var best rank
	var winners []*Assignment
	d := &Decision{Reason: "no_permission"}
	for _, a := range s.Assignments {
		if a.DefID != q.DefID || !a.InDates(now) {
			continue
		}
		r := rank{}
		switch {
		case a.NameID == q.NameID:
			r.res = 1
		case cl.names[a.NameID][q.NameID]:
		default:
			continue
		}
		switch {
		case a.ActionID == q.ActionID:
			r.act = 1
		case cl.actions[a.ActionID][q.ActionID]:
		default:
			continue
		}
		switch {
		case a.Subject != nil:
			if *a.Subject != sub.Identity || !sub.Roles[a.Role] {
				continue
			}
			r.src = SrcSubject
		case sub.Roles[a.Role]:
			r.src = SrcNested
			if sub.Direct[a.Role] {
				r.src = SrcDirect
			}
		default:
			continue
		}
		if ctx != nil && len(a.Limits) > 0 {
			c, err := CompileLimits(a.Limits)
			switch {
			case err != nil && a.Disallowed:
				// fail closed: a deny whose limit cannot be read stays in force
			case a.Disallowed:
				// fail closed: a deny whose limit needs a context value that is
				// missing or malformed stays in force; only a limit that was
				// evaluated and failed sets it aside
				ok, miss := HoldsClosed(c, ctx)
				if !ok {
					d.LimitsFailed = append(d.LimitsFailed, a.ID)
					continue
				}
				for _, k := range miss {
					if !slices.Contains(d.ContextMissing, k) {
						d.ContextMissing = append(d.ContextMissing, k)
					}
				}
			case err != nil || !c.Holds(ctx): // an allow whose limit does not compile never holds
				d.LimitsFailed = append(d.LimitsFailed, a.ID)
				continue
			}
		}
		switch {
		case winners == nil || r.better(best):
			best, winners = r, []*Assignment{a}
		case !best.better(r):
			winners = append(winners, a)
		}
	}
	if winners == nil {
		return d, nil
	}
	d.Via = winners
	d.Allowed, d.Reason = true, "allowed"
	for _, a := range winners {
		if a.Disallowed {
			d.Allowed, d.Reason = false, "disallowed"
			break
		}
	}
	if ctx == nil {
		// Without a context the verdict is conditional when every assignment that
		// decides it (the allows of an allow, the disallows of a deny) has limits.
		// A limited deny holds unless a limit is evaluated and fails, and also when
		// a context value is missing (fail closed).
		d.Conditional = true
		for _, a := range winners {
			if a.Disallowed == d.Allowed {
				continue
			}
			if len(a.Limits) == 0 {
				d.Conditional = false
			}
		}
	}
	return d, nil
}

// Effect is one effective permission of an identity.
type Effect struct {
	Resource    string
	Action      string
	Allowed     bool
	Conditional bool
	Via         []*Assignment
}

// MaxEntries bounds the effective permissions one call computes.
const MaxEntries = 5000

// Effective lists what an identity can do at now: every (resource, action)
// covered by an assignment that reaches it, directly or through inheritance, with
// the heuristics' verdict. Limits are reported (Conditional), not evaluated.
// Truncated says the list hit MaxEntries.
func (s *Set) Effective(sub Subject, now time.Time) (out []Effect, truncated bool, err error) {
	type pair struct{ def, name, action string }
	seen := map[pair]bool{}
	var pairs []pair
collect:
	for _, a := range s.Assignments {
		if !a.InDates(now) {
			continue
		}
		if a.Subject != nil && (*a.Subject != sub.Identity || !sub.Roles[a.Role]) || a.Subject == nil && !sub.Roles[a.Role] {
			continue
		}
		cl, err := s.closure(a.DefID)
		if err != nil {
			return nil, false, err
		}
		for _, n := range withSelf(a.NameID, cl.names[a.NameID]) {
			for _, ac := range withSelf(a.ActionID, cl.actions[a.ActionID]) {
				if p := (pair{a.DefID, n, ac}); !seen[p] {
					if len(pairs) >= MaxEntries { // the expansion is bounded too, not only the output
						truncated = true
						break collect
					}
					seen[p] = true
					pairs = append(pairs, p)
				}
			}
		}
	}
	for _, p := range pairs {
		res, err := s.fullName(p.name)
		if err != nil {
			return nil, false, err
		}
		act, err := s.actionNameOf(p.action)
		if err != nil {
			return nil, false, err
		}
		d, err := s.Decide(sub, Query{DefID: p.def, NameID: p.name, ActionID: p.action, Resource: res, Action: act}, nil, now)
		if err != nil {
			return nil, false, err
		}
		out = append(out, Effect{Resource: res, Action: act, Allowed: d.Allowed, Conditional: d.Conditional, Via: d.Via})
	}
	slices.SortFunc(out, func(a, b Effect) int {
		if c := strings.Compare(a.Resource, b.Resource); c != 0 {
			return c
		}
		return strings.Compare(a.Action, b.Action)
	})
	return out, truncated, nil
}

func withSelf(id string, implied map[string]bool) []string {
	out := make([]string, 0, len(implied)+1)
	out = append(out, id)
	for k := range implied {
		out = append(out, k)
	}
	return out
}
