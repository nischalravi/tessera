package model

import (
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Direct memberships and composite definitions (issue #45, GR-2; design §6).
// The service validates, writes the stored inputs, hands the engine the work
// and writes the domain audit event, all in the caller's transaction. When the
// engine's work does not fit the synchronous budget the direct change still
// commits and the Outcome says the recompute is queued.

// Outcome is engine.Outcome: whether the recompute was queued, and its op id.
type Outcome = engine.Outcome

// MaxReason bounds a membership's reason text.
const MaxReason = 4096

// MemberInput names the member of an add: an identity (Identity) or a group
// (Group), with optional dates and a reason.
type MemberInput struct {
	Identity    *int64
	Group       store.GroupID
	EnabledFrom *time.Time
	DisabledAt  *time.Time
	Reason      string
	// Source and SourceRef say where a new row comes from (default api; a rule
	// that adds a member says rule and its id).
	Source    string
	SourceRef string
}

// AddResult is the stored row, whether it is new (an add of an existing member
// updates its dates and reason) and what the engine did.
type AddResult struct {
	Member  *store.DirectMembership
	Created bool
	Outcome Outcome
}

func groupIDStrings(ids []store.GroupID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

// engineErr maps an engine refusal to the API's: a cycle is 409 with the path
// of group names.
func (e Env) engineErr(err error) error {
	ce, ok := engine.IsCycle(err)
	if !ok {
		return err
	}
	names := make([]string, len(ce.Path))
	for i, id := range ce.Path {
		names[i] = string(id)
		if g, err := e.Tx.GrpGroup(id); err == nil {
			names[i] = g.Name
		}
	}
	x := conflict("cycle", "the change would make a group a member of itself, directly or through other groups")
	x.Extra = map[string]any{"path": names}
	return x
}

// writableGroup returns a group that can take membership changes by hand: not
// deleted, not in or of a mirrored folder and not filled by a loader (its
// loader is its only writer; see LoaderSync).
func (e Env) writableGroup(id store.GroupID) (*store.NativeGroup, error) {
	g, _, err := e.liveGroup(id)
	if err != nil {
		return nil, err
	}
	if g.ManagedBy == store.ManagedByGrouperMirror {
		return nil, conflict("folder_mirrored", "group %q is mirrored from Grouper and is read-only here", g.Name)
	}
	if g.ManagedBy == store.ManagedByLoader {
		return nil, loaderManaged(g)
	}
	return g, nil
}

func (e Env) checkDates(from, to *time.Time) error {
	if from != nil && to != nil && !to.After(*from) {
		return invalid("invalid_dates", "disabled_at must be after enabled_from")
	}
	if to != nil && !to.After(e.Now) {
		return invalid("invalid_dates", "disabled_at must be in the future")
	}
	return nil
}

// AddMember adds an identity or a group to a group's members list, or updates
// the dates and reason of the row that is already there. A composite takes no
// direct members; a group cannot be added if that makes a cycle.
func (e Env) AddMember(id store.GroupID, in MemberInput) (*AddResult, error) {
	g, err := e.writableGroup(id)
	if err != nil {
		return nil, err
	}
	if g.Definition != store.DefinitionBasic {
		return nil, conflict("composite_no_members", "group %q is a composite: its members come from its factors", g.Name)
	}
	if (in.Identity == nil) == (in.Group == "") {
		return nil, invalid("invalid_member", "name exactly one of identity or group")
	}
	if err := errors.Join(e.checkDates(in.EnabledFrom, in.DisabledAt), checkText("reason", in.Reason, MaxReason)); err != nil {
		return nil, firstErr(err)
	}
	if err := engine.Touch(e.Tx, e.Now); err != nil {
		return nil, err
	}
	list := store.MembersListID(e.Tx.Tenant())
	typ, key := store.MemberIdentity, ""
	var child *store.NativeGroup
	if in.Identity != nil {
		if _, err := e.Tx.Identity(*in.Identity); errors.Is(err, store.ErrNotFound) {
			return nil, invalid("unknown_identity", "no such identity")
		} else if err != nil {
			return nil, err
		}
		key = strconv.FormatInt(*in.Identity, 10)
	} else {
		typ, key = store.MemberGroup, string(in.Group)
		if child, err = e.Tx.GrpGroup(in.Group); errors.Is(err, store.ErrNotFound) {
			return nil, invalid("unknown_group", "no such group")
		} else if err != nil {
			return nil, err
		}
		if child.Status == store.GroupDeleted {
			return nil, conflict("member_group_deleted", "group %q is deleted", child.Name)
		}
	}
	m, err := e.Tx.GrpDirectFind(g.ID, list, typ, key)
	created := errors.Is(err, store.ErrNotFound)
	if err != nil && !created {
		return nil, err
	}
	if created {
		if child != nil {
			if err := e.eng().CheckCycle(e.Tx, g.ID, child.ID); err != nil {
				return nil, e.engineErr(err)
			}
		}
		source := in.Source
		if source == "" {
			source = "api"
		}
		// rules may veto a new identity row (membership require, one group only, ...)
		if child == nil && e.Guard != nil {
			if err := e.Guard.VetoAdd(e, g, *in.Identity, source); err != nil {
				return nil, err
			}
		}
		m = &store.DirectMembership{GroupID: g.ID, ListID: list, MemberType: typ, Source: source, SourceRef: ownerPtr(in.SourceRef),
			CreatedBy: e.By, CreatedAt: e.Now}
		if child != nil {
			m.MemberGroup = &child.ID
		} else {
			m.MemberIdentity = in.Identity
		}
	}
	m.EnabledFrom, m.DisabledAt = in.EnabledFrom, in.DisabledAt
	m.Reason = ownerPtr(in.Reason)
	if created {
		err = e.Tx.InsertGrpDirect(m)
	} else {
		err = e.Tx.SetGrpDirectDates(m)
	}
	if err != nil {
		return nil, err
	}
	evType := events.MembershipDirectAdded
	if !created {
		evType = events.MembershipDirectDatesChanged
	}
	if err := e.emitDirect(evType, m); err != nil {
		return nil, err
	}
	var out Outcome
	if child != nil {
		if created {
			if err := e.eng().AddEdge(e.Tx, store.GrpDep{Parent: g.ID, Child: child.ID, Kind: store.DepNest, List: list}); err != nil {
				return nil, e.engineErr(err)
			}
		}
		out, err = e.eng().RecomputeMembersOf(e.Tx, e.Now, g.ID, child.ID, list)
	} else {
		out, err = e.eng().RecomputeSeeds(e.Tx, e.Now, g.ID, list, []int64{*in.Identity})
	}
	if err != nil {
		return nil, e.engineErr(err)
	}
	action := "groups.member.added"
	if !created {
		action = "groups.member.updated"
	}
	detail := ojson.Object{{Key: "group_id", Value: string(g.ID)}, {Key: "name", Value: g.Name},
		{Key: "member_type", Value: string(typ)}, {Key: "member", Value: key}, {Key: "queued", Value: out.Queued}}
	if m.EnabledFrom != nil {
		detail = append(detail, ojson.KV{Key: "enabled_from", Value: *m.EnabledFrom})
	}
	if m.DisabledAt != nil {
		detail = append(detail, ojson.KV{Key: "disabled_at", Value: *m.DisabledAt})
	}
	if out.Queued {
		detail = append(detail, ojson.KV{Key: "op", Value: out.Op})
	}
	return &AddResult{Member: m, Created: created, Outcome: out}, e.audit(action, "group", string(g.ID), detail)
}

var digitsRE = regexp.MustCompile(`^[0-9]{1,18}$`)

// ParseMember reads the {member} of a members route: an identity id (digits)
// or a group id (a UUID).
func ParseMember(s string) (store.MemberType, string, bool) {
	switch {
	case digitsRE.MatchString(s):
		return store.MemberIdentity, s, true
	case len(s) == 36:
		return store.MemberGroup, s, true
	}
	return "", "", false
}

// RemoveMember removes the direct membership of an identity (id digits) or a
// group (a UUID) from a group's members list.
func (e Env) RemoveMember(id store.GroupID, member string) (Outcome, error) {
	g, err := e.writableGroup(id)
	if err != nil {
		return Outcome{}, err
	}
	typ, key, ok := ParseMember(member)
	if !ok {
		return Outcome{}, invalid("invalid_member", "member is an identity id or a group id")
	}
	if err := engine.Touch(e.Tx, e.Now); err != nil {
		return Outcome{}, err
	}
	list := store.MembersListID(e.Tx.Tenant())
	m, err := e.Tx.GrpDirectFind(g.ID, list, typ, key)
	if errors.Is(err, store.ErrNotFound) {
		return Outcome{}, notFound("no such membership")
	}
	if err != nil {
		return Outcome{}, err
	}
	// the membership's attribute assignments end with it
	if _, err := attrs.RemoveAllOf(e.Attrs(), attrs.Owner{Type: store.AttrOwnerMembership, ID: m.ID}); err != nil {
		return Outcome{}, err
	}
	if err := e.Tx.DeleteGrpDirect(m.ID); err != nil {
		return Outcome{}, err
	}
	if err := e.emitDirect(events.MembershipDirectRemoved, m); err != nil {
		return Outcome{}, err
	}
	var out Outcome
	if typ == store.MemberGroup {
		if err := e.eng().RemoveEdge(e.Tx, store.GrpDep{Parent: g.ID, Child: *m.MemberGroup, Kind: store.DepNest, List: list}); err != nil {
			return Outcome{}, e.engineErr(err)
		}
		out, err = e.eng().RecomputeMembersOf(e.Tx, e.Now, g.ID, *m.MemberGroup, list)
	} else {
		out, err = e.eng().RecomputeSeeds(e.Tx, e.Now, g.ID, list, []int64{*m.MemberIdentity})
	}
	if err != nil {
		return Outcome{}, e.engineErr(err)
	}
	detail := ojson.Object{{Key: "group_id", Value: string(g.ID)}, {Key: "name", Value: g.Name},
		{Key: "member_type", Value: string(typ)}, {Key: "member", Value: key}, {Key: "queued", Value: out.Queued}}
	if out.Queued {
		detail = append(detail, ojson.KV{Key: "op", Value: out.Op})
	}
	return out, e.audit("groups.member.removed", "group", string(g.ID), detail)
}

// ---------------------------------------------------------------- composites

// CompositeInput defines a composite: an operator over factor groups.
type CompositeInput struct {
	Op      store.CompositeOp
	Factors []store.GroupID
	// DiscardMembers lets ConvertToComposite delete the group's direct
	// memberships (a composite has none); without it they are a 409.
	DiscardMembers bool
}

// checkFactors validates a composite definition for group self ("" when the
// group is being created): the operator and its factor count, and that every
// factor exists, is not deleted and appears once. A factor that is the group
// itself, or that would close a cycle, is refused by the engine as a cycle.
func (e Env) checkFactors(self store.GroupID, op store.CompositeOp, factors []store.GroupID) error {
	if !engine.ValidOp(op, len(factors)) {
		return invalid("invalid_composite", "union and intersection need 2 to %d factors, complement exactly 2", engine.MaxFactors)
	}
	seen := map[store.GroupID]bool{}
	for _, f := range factors {
		if seen[f] {
			return invalid("duplicate_factor", "factor %s is listed twice", f)
		}
		seen[f] = true
		fg, err := e.Tx.GrpGroup(f)
		if errors.Is(err, store.ErrNotFound) {
			return invalid("unknown_factor", "no such group: %s", f)
		}
		if err != nil {
			return err
		}
		if fg.Status == store.GroupDeleted {
			return conflict("factor_deleted", "factor %q is deleted", fg.Name)
		}
	}
	return nil
}

// ConvertToComposite turns a basic group into a composite in place. A basic
// group's direct memberships do not survive the conversion, so they are a 409
// unless DiscardMembers is set; nesting rows are removed from the dependency
// graph with them. The group's members are then recomputed from the factors.
func (e Env) ConvertToComposite(id store.GroupID, in CompositeInput) (*store.NativeGroup, Outcome, error) {
	g, err := e.writableGroup(id)
	if err != nil {
		return nil, Outcome{}, err
	}
	if g.Definition != store.DefinitionBasic {
		return nil, Outcome{}, conflict("not_basic", "group %q is already a composite or policy group", g.Name)
	}
	if err := e.checkFactors(g.ID, in.Op, in.Factors); err != nil {
		return nil, Outcome{}, err
	}
	if err := engine.Touch(e.Tx, e.Now); err != nil {
		return nil, Outcome{}, err
	}
	n, err := e.Tx.GrpDirectCount(store.GrpDirectFilter{Group: g.ID})
	if err != nil {
		return nil, Outcome{}, err
	}
	if n > 0 && !in.DiscardMembers {
		x := conflict("has_direct_members", "group %q has %d direct membership(s); a composite has none (discard them to convert)", g.Name, n)
		x.Extra = map[string]any{"direct_members": n}
		return nil, Outcome{}, x
	}
	if n > 0 {
		if err := e.dropDirect(g.ID); err != nil {
			return nil, Outcome{}, err
		}
	}
	op := in.Op
	if err := e.Tx.SetGrpGroupDefinition(g.ID, store.DefinitionComposite, &op); err != nil {
		return nil, Outcome{}, err
	}
	if err := e.eng().SetFactors(e.Tx, e.Now, g.ID, in.Factors); err != nil {
		return nil, Outcome{}, e.engineErr(err)
	}
	if err := e.definitionChanged(g.ID); err != nil {
		return nil, Outcome{}, err
	}
	out, err := e.eng().RecomputeGroup(e.Tx, e.Now, g.ID)
	if err != nil {
		return nil, Outcome{}, e.engineErr(err)
	}
	if g, err = e.Group(g.ID); err != nil {
		return nil, Outcome{}, err
	}
	return g, out, e.audit("groups.group.converted", "group", string(g.ID), ojson.Object{{Key: "group_id", Value: string(g.ID)},
		{Key: "name", Value: g.Name}, {Key: "op", Value: string(in.Op)}, {Key: "factors", Value: groupIDStrings(in.Factors)},
		{Key: "discarded_members", Value: int64(n)}, {Key: "queued", Value: out.Queued}})
}

// dropDirect deletes every direct membership of a group, taking its nesting
// edges out of the dependency graph first.
func (e Env) dropDirect(g store.GroupID) error {
	for off := 0; ; {
		rows, err := e.Tx.GrpDirect(store.GrpDirectFilter{Group: g, Limit: 500, Offset: off})
		if err != nil {
			return err
		}
		for _, m := range rows {
			if m.MemberType == store.MemberGroup {
				if err := e.eng().RemoveEdge(e.Tx, store.GrpDep{Parent: g, Child: *m.MemberGroup, Kind: store.DepNest, List: m.ListID}); err != nil {
					return err
				}
			}
			if _, err := attrs.RemoveAllOf(e.Attrs(), attrs.Owner{Type: store.AttrOwnerMembership, ID: m.ID}); err != nil {
				return err
			}
			if err := e.emitDirect(events.MembershipDirectRemoved, m); err != nil {
				return err
			}
		}
		if len(rows) < 500 {
			break
		}
		off += len(rows)
	}
	_, err := e.Tx.DeleteGrpDirectOf(g)
	return err
}

// definitionChanged writes the group.definition_changed event of a group whose
// definition (basic to composite, or a new operator or factor list) was just stored.
func (e Env) definitionChanged(id store.GroupID) error {
	g, err := e.Group(id)
	if err != nil {
		return err
	}
	return e.emitGroup(events.GroupDefinitionChanged, g, nil)
}

// SetComposite redefines a composite group: a new operator and factor list.
// Members are recomputed over the old members and the new factors' members.
func (e Env) SetComposite(id store.GroupID, in CompositeInput) (*store.NativeGroup, Outcome, error) {
	g, err := e.writableGroup(id)
	if err != nil {
		return nil, Outcome{}, err
	}
	if g.Definition != store.DefinitionComposite {
		return nil, Outcome{}, conflict("not_composite", "group %q is not a composite group", g.Name)
	}
	if err := e.checkFactors(g.ID, in.Op, in.Factors); err != nil {
		return nil, Outcome{}, err
	}
	if err := engine.Touch(e.Tx, e.Now); err != nil {
		return nil, Outcome{}, err
	}
	op := in.Op
	if err := e.Tx.SetGrpGroupDefinition(g.ID, store.DefinitionComposite, &op); err != nil {
		return nil, Outcome{}, err
	}
	if err := e.eng().SetFactors(e.Tx, e.Now, g.ID, in.Factors); err != nil {
		return nil, Outcome{}, e.engineErr(err)
	}
	if err := e.definitionChanged(g.ID); err != nil {
		return nil, Outcome{}, err
	}
	out, err := e.eng().RecomputeGroup(e.Tx, e.Now, g.ID)
	if err != nil {
		return nil, Outcome{}, e.engineErr(err)
	}
	if g, err = e.Group(g.ID); err != nil {
		return nil, Outcome{}, err
	}
	return g, out, e.audit("groups.composite.updated", "group", string(g.ID), ojson.Object{{Key: "group_id", Value: string(g.ID)},
		{Key: "name", Value: g.Name}, {Key: "op", Value: string(in.Op)}, {Key: "factors", Value: groupIDStrings(in.Factors)},
		{Key: "queued", Value: out.Queued}})
}

// Factors returns a composite's factors in order (nil for other groups).
func (e Env) Factors(id store.GroupID) ([]store.GroupID, error) { return e.Tx.GrpFactors(id) }

// ---------------------------------------------------------------- reads

// MemberQuery pages and narrows a members listing. Q is a case-insensitive
// substring of the member's name (or email); Sort is name, -name, since or
// -since; Enabled ("true" or "false") keeps the direct rows that count (or not)
// right now; Indirect keeps the effective members without an active direct row.
type MemberQuery struct {
	Limit    int
	Offset   int
	Q        string
	Sort     string
	Enabled  string
	Indirect bool
}

// DirectMember is a direct membership with the member's name and whether the
// row counts right now.
type DirectMember struct {
	*store.DirectMembership
	Name   string
	Active bool
}

// DirectMembers lists a group's direct memberships in its members list.
func (e Env) DirectMembers(id store.GroupID, q MemberQuery) ([]DirectMember, int, error) {
	if _, err := e.Group(id); err != nil {
		return nil, 0, err
	}
	list := store.MembersListID(e.Tx.Tenant())
	rows, total, err := e.Tx.GrpDirectSearch(store.MemberSearch{Group: id, List: list, Q: q.Q, Sort: q.Sort, Enabled: q.Enabled,
		Now: e.Now, Limit: q.Limit, Offset: q.Offset})
	if err != nil {
		return nil, 0, err
	}
	out := make([]DirectMember, len(rows))
	for i, m := range rows {
		out[i] = DirectMember{DirectMembership: m, Active: (m.EnabledFrom == nil || !m.EnabledFrom.After(e.Now)) &&
			(m.DisabledAt == nil || e.Now.Before(*m.DisabledAt))}
		if m.MemberIdentity != nil {
			if ident, err := e.Tx.Identity(*m.MemberIdentity); err == nil {
				out[i].Name = ident.Name
			}
		} else if m.MemberGroup != nil {
			if g, err := e.Tx.GrpGroup(*m.MemberGroup); err == nil {
				out[i].Name = g.Name
			}
		}
	}
	return out, total, nil
}

// EffectiveMember is one effective member of a group.
type EffectiveMember struct {
	Identity int64
	Name     string
	Support  int32
	Since    time.Time
}

// EffectiveMembers lists a group's effective members by identity id, and says
// whether the group is stale (a recompute is pending).
func (e Env) EffectiveMembers(id store.GroupID, q MemberQuery) (out []EffectiveMember, total int, stale bool, err error) {
	g, err := e.Group(id)
	if err != nil {
		return nil, 0, false, err
	}
	list := store.MembersListID(e.Tx.Tenant())
	rows, total, err := e.Tx.GrpEffectiveSearch(store.MemberSearch{Group: id, List: list, Q: q.Q, Sort: q.Sort, Indirect: q.Indirect,
		Now: e.Now, Limit: q.Limit, Offset: q.Offset})
	if err != nil {
		return nil, 0, false, err
	}
	for _, r := range rows {
		m := EffectiveMember{Identity: r.Identity, Support: r.Support, Since: r.Since}
		if ident, err := e.Tx.Identity(r.Identity); err == nil {
			m.Name = ident.Name
		}
		out = append(out, m)
	}
	return out, total, g.RecomputeState != "clean", nil
}

// IsMember answers "is the identity a member of the group now" for the
// built-in members list. It ignores memberships whose dates have passed even
// if the time wheel has not yet removed them.
func (e Env) IsMember(id store.GroupID, identity int64) (bool, error) {
	if _, err := e.Group(id); err != nil {
		return false, err
	}
	if _, err := e.Tx.Identity(identity); errors.Is(err, store.ErrNotFound) {
		return false, notFound("no such identity")
	} else if err != nil {
		return false, err
	}
	return e.eng().IsMember(e.Tx, e.Now, id, store.MembersListID(e.Tx.Tenant()), identity)
}
