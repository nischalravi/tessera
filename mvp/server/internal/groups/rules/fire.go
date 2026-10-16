package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Consumer is the rules runner's cursor name in grp_event_cursors.
const Consumer = "rules"

// fireEvent is what a rule is evaluated against: a membership change of an
// identity in a group, or the creation of a group or folder.
type fireEvent struct {
	Type     string
	Seq      int64 // 0 for a synchronous veto check
	At       time.Time
	Group    *store.NativeGroup // the group of a membership change, or the new group
	Identity *int64
	Actor    *int64 // the identity behind the request, when known
	Source   string // of a direct membership row
	Created  string // id of the new group or folder
	Name     string // full name of the new group or folder
	Parent   store.FolderID
	CauseRef string
}

// ---------------------------------------------------------------- where a rule applies

// scope answers "is this object under the rule's owner", caching folders.
type scope struct {
	tx      *store.TenantTx
	folders map[store.FolderID]*store.Folder
}

func newScope(tx *store.TenantTx) *scope {
	return &scope{tx: tx, folders: map[store.FolderID]*store.Folder{}}
}

// maxDepth bounds the walk up the folder tree.
const maxDepth = 256

// chain returns the folder and its ancestors, nearest first.
func (sc *scope) chain(id store.FolderID) ([]store.FolderID, error) {
	var out []store.FolderID
	for cur := &id; cur != nil && len(out) < maxDepth; {
		f, ok := sc.folders[*cur]
		if !ok {
			var err error
			if f, err = sc.tx.GrpFolder(*cur); errors.Is(err, store.ErrNotFound) {
				f, err = nil, nil
			} else if err != nil {
				return nil, err
			}
			sc.folders[*cur] = f
		}
		if f == nil {
			break
		}
		out = append(out, f.ID)
		cur = f.ParentID
	}
	return out, nil
}

// under reports whether a rule owned by the folder with the scope covers
// something that sits in folder in.
func (sc *scope) under(owner string, scp string, in store.FolderID) (bool, error) {
	ch, err := sc.chain(in)
	if err != nil || len(ch) == 0 {
		return false, err
	}
	switch scp {
	case "one":
		return string(ch[0]) == owner, nil
	case "sub":
		return slices.Contains(ch, store.FolderID(owner)), nil
	}
	return false, nil
}

// covers reports whether the rule applies to membership changes of group g.
func (sc *scope) covers(r *store.GrpRule, g *store.NativeGroup) (bool, error) {
	if r.OwnerType == store.RuleOwnerGroup {
		return r.OwnerID == string(g.ID), nil
	}
	return sc.under(r.OwnerID, r.Scope, g.FolderID)
}

// ---------------------------------------------------------------- conditions

// holds reports whether every condition is true for the event.
func (rt *Runtime) holds(tx *store.TenantTx, now time.Time, conds []Condition, ev *fireEvent) (bool, error) {
	for _, c := range conds {
		ok, err := rt.holdsOne(tx, now, c, ev)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func (rt *Runtime) holdsOne(tx *store.TenantTx, now time.Time, c Condition, ev *fireEvent) (bool, error) {
	switch c.Type {
	case CondIdentityAttribute:
		if ev.Identity == nil {
			return false, nil
		}
		i, err := tx.Identity(*ev.Identity)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		var v string
		switch c.Attribute {
		case "department":
			v = deref(i.Department)
		case "title":
			v = deref(i.Title)
		case "type":
			v = i.Type
		case "status":
			v = i.Status
		}
		return slices.Contains(c.Values, v), nil // equals has one value
	case CondIdentityInGroup, CondIdentityNotInGrp:
		if ev.Identity == nil {
			return false, nil
		}
		in, err := rt.engine().IsMember(tx, now, store.GroupID(c.Group), store.MembersListID(tx.Tenant()), *ev.Identity)
		if err != nil {
			return false, err
		}
		return in == (c.Type == CondIdentityInGroup), nil
	case CondMembershipSource:
		return ev.Source == c.Source, nil
	case CondNameMatches:
		ok, err := path.Match(c.Pattern, ev.Name)
		return ok && err == nil, nil
	}
	return false, nil // a condition outside the vocabulary never holds
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ---------------------------------------------------------------- synchronous veto

type guard struct{ rt *Runtime }

// Guard returns the model.Guard that applies the veto rules.
func (rt *Runtime) Guard() model.Guard { return guard{rt} }

// VetoAdd implements model.Guard.
func (g guard) VetoAdd(e model.Env, grp *store.NativeGroup, identity int64, source string) error {
	return g.rt.veto(e, grp, identity, source)
}

// veto runs the rules that deny a direct add of an identity to a group. They
// run in the request's transaction, before the row is written, and fail
// closed: a rule that cannot be evaluated (its author lost the privileges it
// needs, its hook does not answer, its row is damaged) refuses the add.
func (rt *Runtime) veto(e model.Env, grp *store.NativeGroup, identity int64, source string) error {
	rs, err := e.Tx.GrpRulesEnabled(TrigDirectAdded, "")
	if err != nil || len(rs) == 0 {
		return err
	}
	sc := newScope(e.Tx)
	ev := &fireEvent{Type: TrigDirectAdded, At: e.Now, Group: grp, Identity: &identity, Actor: e.ByIdentity, Source: source}
	for _, r := range rs {
		in, err := sc.covers(r, grp)
		if err != nil {
			return err
		}
		if !in {
			continue
		}
		c, err := Compile(r)
		if err != nil {
			return model.Vetoed(fmt.Sprintf("rule %q cannot be read, so the change is refused", r.Name), r.ID)
		}
		if !c.Spec.IsVeto() {
			continue
		}
		ok, err := rt.holds(e.Tx, e.Now, c.Spec.Conditions, ev)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		au, err := rt.authorize(e.Tx, e.Now, c)
		if err != nil {
			return err
		}
		if au.Denied != "" {
			return model.Vetoed(fmt.Sprintf("rule %q cannot be enforced (%s), so the change is refused", r.Name, au.Denied), r.ID)
		}
		msg, err := rt.denies(e, sc, c, ev)
		if err != nil {
			return err
		}
		if msg != "" {
			return model.Vetoed(msg, r.ID)
		}
	}
	return nil
}

// denies returns the veto message of a rule whose conditions hold, or "".
func (rt *Runtime) denies(e model.Env, sc *scope, c *Compiled, ev *fireEvent) (string, error) {
	who := fmt.Sprintf("identity %d", *ev.Identity)
	if i, err := e.Tx.Identity(*ev.Identity); err == nil {
		who = i.Name
	}
	switch c.Spec.Action {
	case ActVeto:
		return c.Spec.Params.Message, nil
	case ActNoSelfAdd:
		if ev.Actor != nil && *ev.Actor == *ev.Identity {
			return fmt.Sprintf("you cannot add yourself to %s", ev.Group.Name), nil
		}
	case ActRequireMemberOf:
		need := store.GroupID(c.Spec.Params.Group)
		in, err := rt.engine().IsMember(e.Tx, e.Now, need, store.MembersListID(e.Tx.Tenant()), *ev.Identity)
		if err != nil || in {
			return "", err
		}
		name := string(need)
		if g, err := e.Tx.GrpGroup(need); err == nil {
			name = g.Name
		}
		return fmt.Sprintf("%s must be a member of %s before joining %s", who, name, ev.Group.Name), nil
	case ActOneGroupOnly:
		held, err := e.Tx.GrpDirectIdentityGroups(store.MembersListID(e.Tx.Tenant()), *ev.Identity, e.Now)
		if err != nil {
			return "", err
		}
		for _, id := range held {
			if id == ev.Group.ID {
				continue
			}
			other, err := e.Tx.GrpGroup(id)
			if err != nil {
				return "", err
			}
			if in, err := sc.covers(c.Rule, other); err != nil {
				return "", err
			} else if in {
				return fmt.Sprintf("%s is already in %s: only one group of this folder is allowed", who, other.Name), nil
			}
		}
	case ActWebhook:
		return rt.hookVerdict(e.Tx.Context(), e.Tx.Tenant(), c, ev, e.Now), nil
	}
	return "", nil
}

// ---------------------------------------------------------------- reacting to events

// Process reads up to limit events after the "rules" cursor, fires the rules
// that react to them and moves the cursor, all in tx. It returns how many
// events it read. A rule's action runs with the authority its author holds
// now: one that no longer holds the privileges is recorded as denied and does
// nothing.
func (rt *Runtime) Process(tx *store.TenantTx, now time.Time, limit int) (int, error) {
	evs, err := events.Poll(tx, Consumer, limit)
	if err != nil || len(evs) == 0 {
		return 0, err
	}
	for _, ev := range evs {
		if err := rt.handle(tx, now, ev); err != nil {
			return 0, fmt.Errorf("rules: event %d (%s): %w", ev.Seq, ev.Type, err)
		}
	}
	return len(evs), events.Ack(tx, Consumer, evs[len(evs)-1].Seq, now)
}

// directSource is the part of a direct membership event's data that rules read.
type directSource struct {
	Source string `json:"source"`
}

// fireEventOf turns a stored event into what rules look at; ok is false for an
// event no rule reacts to.
func (rt *Runtime) fireEventOf(tx *store.TenantTx, ev *store.GrpEvent) (*fireEvent, bool, error) {
	fe := &fireEvent{Type: ev.Type, Seq: ev.Seq, At: ev.OccurredAt, CauseRef: ev.CauseRef}
	switch ev.Type {
	case TrigDirectAdded, TrigDirectRemoved, TrigEffectiveAdded, TrigEffectiveRemoved:
		if ev.Identity == nil || ev.List != string(store.MembersListID(tx.Tenant())) {
			return nil, false, nil
		}
		g, err := tx.GrpGroup(store.GroupID(ev.ObjectID))
		if errors.Is(err, store.ErrNotFound) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		fe.Group, fe.Identity = g, ev.Identity
		var d directSource
		if len(ev.Data) > 0 && json.Unmarshal(ev.Data, &d) == nil {
			fe.Source = d.Source
		}
		return fe, true, nil
	case TrigGroupCreated:
		g, err := tx.GrpGroup(store.GroupID(ev.ObjectID))
		if errors.Is(err, store.ErrNotFound) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		fe.Group, fe.Created, fe.Name, fe.Parent = g, string(g.ID), g.Name, g.FolderID
		return fe, true, nil
	case TrigFolderCreated:
		f, err := tx.GrpFolder(store.FolderID(ev.ObjectID))
		if errors.Is(err, store.ErrNotFound) || (err == nil && f.ParentID == nil) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		fe.Created, fe.Name, fe.Parent = string(f.ID), f.Name, *f.ParentID
		return fe, true, nil
	}
	return nil, false, nil
}

func (rt *Runtime) handle(tx *store.TenantTx, now time.Time, ev *store.GrpEvent) error {
	fe, ok, err := rt.fireEventOf(tx, ev)
	if err != nil || !ok {
		return err
	}
	sc := newScope(tx)
	if ev.Type == TrigEffectiveRemoved {
		if err := rt.requireRemovals(tx, now, sc, fe); err != nil {
			return err
		}
	}
	rs, err := tx.GrpRulesEnabled(ev.Type, "")
	if err != nil {
		return err
	}
	for _, r := range rs {
		if ev.Seq <= r.ActiveSeq || r.ID == ev.CauseRef {
			continue // a new rule does not act on history, and a rule does not answer its own changes
		}
		var in bool
		if isCreateTrigger(ev.Type) {
			in, err = sc.under(r.OwnerID, r.Scope, fe.Parent)
		} else {
			in, err = sc.covers(r, fe.Group)
		}
		if err != nil || !in {
			if err != nil {
				return err
			}
			continue
		}
		c, err := Compile(r)
		if err != nil {
			rt.log().Error("group rule cannot be read", "rule", r.ID, "err", err)
			continue
		}
		if c.Spec.IsVeto() {
			continue // decided before the change, not after it
		}
		if err := rt.fire(tx, now, sc, c, fe); err != nil {
			return err
		}
	}
	return nil
}

// fire evaluates one rule against an event and acts.
func (rt *Runtime) fire(tx *store.TenantTx, now time.Time, sc *scope, c *Compiled, fe *fireEvent) error {
	ok, err := rt.holds(tx, now, c.Spec.Conditions, fe)
	if err != nil || !ok {
		return err
	}
	au, err := rt.authorize(tx, now, c)
	if err != nil {
		return err
	}
	if au.Denied != "" {
		return rt.record(tx, now, c, fe, "denied", au.Denied)
	}
	result, detail, err := rt.act(tx, now, c, fe, au)
	if err != nil {
		return err
	}
	return rt.record(tx, now, c, fe, result, detail)
}

// Results of a firing, as the rule.fired event records them.
const (
	ResultApplied = "applied"
	ResultSkipped = "skipped"
	ResultVetoed  = "vetoed"
	ResultFailed  = "failed"
	ResultDenied  = "denied"
)

// refusal turns an expected refusal of an operation (a model, privilege or
// rules error) into a "failed" result with its code; anything else is a real error.
func refusal(err error) (string, bool) {
	var me *model.Error
	var pe *privs.Error
	var de *privs.DeniedError
	var re *Error
	switch {
	case errors.As(err, &me):
		if me.Code == "vetoed" {
			return "vetoed by another rule: " + me.Msg, true
		}
		return me.Code, true
	case errors.As(err, &pe):
		return pe.Code, true
	case errors.As(err, &de):
		return "privilege_required: " + string(de.Privilege), true
	case errors.As(err, &re):
		return re.Code, true
	}
	return "", false
}

// actEnv is the model's operation context for a rule's changes: made as the
// rule's author, with their authority, and caused by the rule.
func (rt *Runtime) actEnv(tx *store.TenantTx, now time.Time, c *Compiled, au authority) model.Env {
	by := c.Rule.UpdatedBy
	return model.Env{Tx: tx, Now: now, By: &by, Engine: rt.engine(), ByIdentity: au.Subject.Identity,
		TenantAdmin: au.Subject.TenantAdmin, Guard: rt.Guard(), Cause: store.CauseRule, CauseRef: c.Rule.ID}
}

// act performs the rule's action.
func (rt *Runtime) act(tx *store.TenantTx, now time.Time, c *Compiled, fe *fireEvent, au authority) (result, detail string, err error) {
	result, detail, err = rt.perform(tx, now, c, fe, au)
	if why, ok := refusal(err); ok {
		if strings.HasPrefix(why, "vetoed") {
			return ResultVetoed, why, nil
		}
		return ResultFailed, why, nil
	}
	return result, detail, err
}

func (rt *Runtime) perform(tx *store.TenantTx, now time.Time, c *Compiled, fe *fireEvent, au authority) (string, string, error) {
	p := c.Spec.Params
	list := store.MembersListID(tx.Tenant())
	switch c.Spec.Action {
	case ActAddDisabledDate:
		m, err := tx.GrpDirectFind(fe.Group.ID, list, store.MemberIdentity, strconv.FormatInt(*fe.Identity, 10))
		if errors.Is(err, store.ErrNotFound) {
			return ResultSkipped, "not_a_member", nil
		}
		if err != nil {
			return "", "", err
		}
		at := now.AddDate(0, 0, p.Days)
		if m.DisabledAt != nil && !m.DisabledAt.After(at) {
			return ResultSkipped, "already_ends_sooner", nil
		}
		_, err = rt.actEnv(tx, now, c, au).AddMember(fe.Group.ID, model.MemberInput{Identity: fe.Identity,
			EnabledFrom: m.EnabledFrom, DisabledAt: &at, Reason: deref(m.Reason)})
		return ResultApplied, "ends " + at.Format(time.RFC3339), err

	case ActRemoveFromGroup:
		_, err := rt.actEnv(tx, now, c, au).RemoveMember(store.GroupID(p.Group), strconv.FormatInt(*fe.Identity, 10))
		var me *model.Error
		if errors.As(err, &me) && me.Kind == model.NotFound {
			return ResultSkipped, "not_a_member", nil
		}
		return ResultApplied, "removed", err

	case ActAddToGroup:
		if _, err := tx.GrpDirectFind(store.GroupID(p.Group), list, store.MemberIdentity, strconv.FormatInt(*fe.Identity, 10)); err == nil {
			return ResultSkipped, "already_a_member", nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return "", "", err
		}
		in := model.MemberInput{Identity: fe.Identity, Source: "rule", SourceRef: c.Rule.ID, Reason: "rule: " + c.Rule.Name}
		if p.Days > 0 {
			at := now.AddDate(0, 0, p.Days)
			in.DisabledAt = &at
		}
		_, err := rt.actEnv(tx, now, c, au).AddMember(store.GroupID(p.Group), in)
		return ResultApplied, "added", err

	case ActAssignPrivilege:
		obj := privs.Object{Type: privs.Group, ID: fe.Created}
		need := privs.Admin
		if fe.Type == TrigFolderCreated {
			obj.Type, need = privs.Folder, privs.StemAdmin
		}
		// the object the action touches: its author must administer it too
		if err := privs.NewChecker(tx, now, rt.engine(), au.Subject).Require(obj, need); err != nil {
			return "", "", err
		}
		holder := privs.IdentityHolder(p.HolderIdentity)
		if p.HolderType == store.HolderGroup {
			holder = privs.GroupHolder(store.GroupID(p.HolderGroup))
		}
		_, _, err := privs.Grant(rt.actEnv(tx, now, c, au).Privs(), privs.GrantInput{Object: obj, Privilege: privs.Privilege(p.Privilege),
			Holder: holder, AppliesTo: p.AppliesTo, Scope: p.Scope, Source: store.PrivSourceTemplate})
		return ResultApplied, "granted " + p.Privilege, err

	case ActNotify:
		set, err := tx.GrpRuleSettings()
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return "", "", err
		}
		if err != nil || !set.EmailEnabled {
			return ResultSkipped, "email_rules_disabled", nil // off until a tenant admin turns it on
		}
		to := p.ToIdentity
		if to == 0 {
			to = *fe.Identity
		}
		i, err := tx.Identity(to)
		if errors.Is(err, store.ErrNotFound) || (err == nil && deref(i.Email) == "") {
			return ResultSkipped, "no_email_address", nil
		}
		if err != nil {
			return "", "", err
		}
		body := strings.NewReplacer("{group}", fe.Group.Name, "{identity}", fmt.Sprint(*fe.Identity)).Replace(p.Message)
		if err := rt.notify(tx.Context(), Notification{Tenant: tx.Tenant(), RuleID: c.Rule.ID, Identity: to,
			Email: deref(i.Email), Subject: p.Subject, Body: body}); err != nil {
			return ResultFailed, "notification_failed", nil
		}
		return ResultApplied, "sent", nil

	case ActWebhook:
		status, _, err := rt.post(tx.Context(), tx.Tenant(), c, payloadOf(c, fe), now)
		switch {
		case err != nil:
			return ResultFailed, "hook_unreachable", nil
		case status < 200 || status > 299:
			return ResultFailed, fmt.Sprintf("hook_status_%d", status), nil
		}
		return ResultApplied, "delivered", nil
	}
	return ResultSkipped, "not_handled_here", nil
}

// requireRemovals is the second half of a membership require (G-28): when an
// identity leaves the required group, it leaves the groups that need it.
func (rt *Runtime) requireRemovals(tx *store.TenantTx, now time.Time, sc *scope, fe *fireEvent) error {
	rs, err := tx.GrpRulesEnabled("", ActRequireMemberOf)
	if err != nil || len(rs) == 0 {
		return err
	}
	list := store.MembersListID(tx.Tenant())
	for _, r := range rs {
		if fe.Seq <= r.ActiveSeq {
			continue
		}
		c, err := Compile(r)
		if err != nil || c.Spec.Params.Group != string(fe.Group.ID) {
			continue
		}
		// someone who is back in the group by the time the event is read keeps what they have
		if back, err := rt.engine().IsMember(tx, now, fe.Group.ID, list, *fe.Identity); err != nil || back {
			if err != nil {
				return err
			}
			continue
		}
		held, err := tx.GrpDirectIdentityGroups(list, *fe.Identity, now)
		if err != nil {
			return err
		}
		var targets []*store.NativeGroup
		for _, id := range held {
			g, err := tx.GrpGroup(id)
			if err != nil {
				return err
			}
			if in, err := sc.covers(r, g); err != nil {
				return err
			} else if in {
				targets = append(targets, g)
			}
		}
		if len(targets) == 0 {
			continue
		}
		if ok, err := rt.holds(tx, now, c.Spec.Conditions, fe); err != nil || !ok {
			if err != nil {
				return err
			}
			continue
		}
		au, err := rt.authorize(tx, now, c)
		if err != nil {
			return err
		}
		if au.Denied != "" {
			if err := rt.record(tx, now, c, fe, ResultDenied, au.Denied); err != nil {
				return err
			}
			continue
		}
		env := rt.actEnv(tx, now, c, au)
		var removed []string
		for _, g := range targets {
			if _, err := env.RemoveMember(g.ID, strconv.FormatInt(*fe.Identity, 10)); err != nil {
				why, ok := refusal(err)
				if !ok {
					return err
				}
				if err := rt.record(tx, now, c, fe, ResultFailed, g.Name+": "+why); err != nil {
					return err
				}
				continue
			}
			removed = append(removed, g.Name)
		}
		if len(removed) > 0 {
			if err := rt.record(tx, now, c, fe, ResultApplied, "removed from "+strings.Join(removed, ", ")); err != nil {
				return err
			}
		}
	}
	return nil
}

// record writes the rule.fired event of a firing, with the audit event, in the
// caller's transaction.
func (rt *Runtime) record(tx *store.TenantTx, now time.Time, c *Compiled, fe *fireEvent, result, detail string) error {
	data := map[string]any{"rule": c.Rule.ID, "name": c.Rule.Name, "trigger": c.Rule.Trigger, "action": c.Rule.Action,
		"event_seq": fe.Seq, "result": result, "detail": detail}
	audit := ojson.Object{{Key: "rule_id", Value: c.Rule.ID}, {Key: "name", Value: c.Rule.Name}, {Key: "trigger", Value: c.Rule.Trigger},
		{Key: "action", Value: c.Rule.Action}, {Key: "event_seq", Value: fe.Seq}, {Key: "result", Value: result}, {Key: "detail", Value: detail}}
	if fe.Group != nil {
		data["group"] = string(fe.Group.ID)
		audit = append(audit, ojson.KV{Key: "group_id", Value: string(fe.Group.ID)})
	}
	if fe.Identity != nil {
		data["identity"] = *fe.Identity
		audit = append(audit, ojson.KV{Key: "identity_id", Value: *fe.Identity})
	}
	ev := events.New(events.RuleFired, c.Rule.ID, now, store.CauseRule)
	ev.CauseRef = c.Rule.ID
	ev.Data = events.Data(data)
	if err := pit.Emit(tx, ev); err != nil {
		return err
	}
	_, err := tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.rule.fired", LegacyActor: "groups", TargetType: "rule",
		TargetID: c.Rule.ID, Detail: audit})
	return err
}
