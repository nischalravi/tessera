// Package rules is the closed-vocabulary rules engine of native groups (issue
// #56, GR-13; design docs/design/groups-grouper-parity.md §10.3, K6).
//
// A rule is owned by a folder or a group and says: when this event happens
// (trigger), and these conditions hold, do this one thing (action). The
// vocabulary is closed: there is no expression language, no script and no
// in-process hook. Anything else happens out of process through a signed
// webhook, which may veto a membership add synchronously.
//
// Authority: a rule needs admin (stem_admin on a folder) on its owner and on
// every object its action touches, checked when it is saved and again every
// time it fires, with the privileges its last author holds then (Grouper's
// GRP-7359, a rules UI that let a user act beyond their privileges, is this
// class). Rules that deny (veto, require, one group only, no self-add) are
// evaluated synchronously before a membership is added, through model.Guard.
// Rules that act (add or remove a member, set a date, assign a privilege,
// notify, call a webhook) react to the group events through the "rules" cursor
// of the outbox (Runtime.Process), so they never slow down the request that
// caused them.
package rules

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Triggers: the event types a rule can react to.
const (
	TrigDirectAdded       = events.MembershipDirectAdded
	TrigDirectRemoved     = events.MembershipDirectRemoved
	TrigEffectiveAdded    = events.MembershipEffectiveAdded
	TrigEffectiveRemoved  = events.MembershipEffectiveRemoved
	TrigGroupCreated      = events.GroupCreated
	TrigFolderCreated     = events.FolderCreated
	maxName               = 200
	maxMessage            = 1000
	maxURL                = 2048
	maxConditions         = 10
	maxValues             = 50
	maxDays               = 3650
	MaxRulesPerOwner      = 50
	maxConditionValueSize = 200
)

// Actions: the closed vocabulary.
const (
	ActVeto            = "veto"
	ActRequireMemberOf = "require_member_of"
	ActOneGroupOnly    = "one_group_only"
	ActNoSelfAdd       = "no_self_add"
	ActAddDisabledDate = "add_disabled_date"
	ActRemoveFromGroup = "remove_from_group"
	ActAddToGroup      = "add_to_group"
	ActAssignPrivilege = "assign_privilege"
	ActNotify          = "notify"
	ActWebhook         = "webhook"
)

// planned are the design's actions that need a part that is not built yet
// (the Inbox and micro-certifications of GR-14, object types of GR-7,
// provisioning marks of GR-11). They are refused with their own error, so a
// client can tell "later" from "never".
var planned = map[string]string{
	"open_inbox_task":           "GR-14",
	"start_micro_certification": "GR-14",
	"assign_object_type":        "GR-7",
	"mark_provisionable":        "GR-11",
}

// Condition types.
const (
	CondIdentityAttribute = "identity_attribute"
	CondIdentityInGroup   = "identity_in_group"
	CondIdentityNotInGrp  = "identity_not_in_group"
	CondMembershipSource  = "membership_source"
	CondNameMatches       = "name_matches"
)

// Condition is one typed test; which fields it uses depends on Type.
type Condition struct {
	Type      string   `json:"type"`
	Attribute string   `json:"attribute,omitempty"` // identity_attribute: department | title | type | status
	Op        string   `json:"op,omitempty"`        // identity_attribute: equals | in
	Values    []string `json:"values,omitempty"`    // identity_attribute
	Group     string   `json:"group,omitempty"`     // identity_in_group, identity_not_in_group
	Source    string   `json:"source,omitempty"`    // membership_source: api | loader | rule | ...
	Pattern   string   `json:"pattern,omitempty"`   // name_matches: a path.Match pattern over the new object's full name
}

// Params are an action's parameters; which fields it uses depends on the action.
type Params struct {
	Message        string `json:"message,omitempty"`         // veto, notify
	Days           int    `json:"days,omitempty"`            // add_disabled_date, add_to_group
	Group          string `json:"group,omitempty"`           // require_member_of, remove_from_group, add_to_group
	Privilege      string `json:"privilege,omitempty"`       // assign_privilege
	HolderType     string `json:"holder_type,omitempty"`     // assign_privilege: identity | group
	HolderIdentity int64  `json:"holder_identity,omitempty"` // assign_privilege
	HolderGroup    string `json:"holder_group,omitempty"`    // assign_privilege
	AppliesTo      string `json:"applies_to,omitempty"`      // assign_privilege on a new folder
	Scope          string `json:"scope,omitempty"`           // assign_privilege on a new folder
	Subject        string `json:"subject,omitempty"`         // notify
	ToIdentity     int64  `json:"to_identity,omitempty"`     // notify: default the member concerned
	URL            string `json:"url,omitempty"`             // webhook
	Veto           bool   `json:"veto,omitempty"`            // webhook: the answer may veto the add
	FailOpen       bool   `json:"fail_open,omitempty"`       // webhook veto: allow when the hook does not answer
}

// Spec is what a client saves.
type Spec struct {
	OwnerType  string
	OwnerID    string
	Scope      string
	Name       string
	Trigger    string
	Conditions []Condition
	Action     string
	Params     Params
	Enabled    bool
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isMembershipTrigger(t string) bool {
	return slices.Contains([]string{TrigDirectAdded, TrigDirectRemoved, TrigEffectiveAdded, TrigEffectiveRemoved}, t)
}

func isCreateTrigger(t string) bool { return t == TrigGroupCreated || t == TrigFolderCreated }

// IsVeto reports whether the rule denies a membership add synchronously.
func (s *Spec) IsVeto() bool {
	switch s.Action {
	case ActVeto, ActRequireMemberOf, ActOneGroupOnly, ActNoSelfAdd:
		return true
	case ActWebhook:
		return s.Params.Veto
	}
	return false
}

func checkGroupID(field, id string) error {
	if !uuidRE.MatchString(id) {
		return invalid("invalid_"+field, "%s must be a group id (a UUID)", field)
	}
	return nil
}

func checkText(field, s string, max int, required bool) error {
	switch {
	case required && strings.TrimSpace(s) == "":
		return invalid("invalid_"+field, "%s is required", field)
	case len(s) > max:
		return invalid("invalid_"+field, "%s is at most %d characters", field, max)
	}
	return nil
}

// Validate checks a spec against the closed vocabulary and normalizes it: a
// folder rule's scope defaults to sub, a group rule's is self.
func (s *Spec) Validate() error {
	switch s.OwnerType {
	case store.RuleOwnerGroup:
		if s.Scope != "" && s.Scope != "self" {
			return invalid("invalid_scope", "a group's rule has scope self")
		}
		s.Scope = "self"
	case store.RuleOwnerFolder:
		if s.Scope == "" {
			s.Scope = "sub"
		}
		if s.Scope != "one" && s.Scope != "sub" {
			return invalid("invalid_scope", "a folder's rule has scope one (the groups directly in it) or sub (everything below)")
		}
	default:
		return invalid("invalid_owner", "a rule is owned by a folder or a group")
	}
	if err := checkText("name", s.Name, maxName, false); err != nil {
		return err
	}
	switch {
	case isMembershipTrigger(s.Trigger):
	case isCreateTrigger(s.Trigger):
		if s.OwnerType != store.RuleOwnerFolder {
			return invalid("invalid_trigger", "%s is a trigger of a folder's rule: it fires for what is created under the folder", s.Trigger)
		}
	default:
		return invalid("invalid_trigger", "%q is not a trigger (%s)", s.Trigger, strings.Join(Triggers(), ", "))
	}
	if err := s.validateConditions(); err != nil {
		return err
	}
	return s.validateAction()
}

// Triggers lists the vocabulary's triggers.
func Triggers() []string {
	return []string{TrigDirectAdded, TrigDirectRemoved, TrigEffectiveAdded, TrigEffectiveRemoved, TrigGroupCreated, TrigFolderCreated}
}

// Actions lists the vocabulary's actions.
func Actions() []string {
	return []string{ActVeto, ActRequireMemberOf, ActOneGroupOnly, ActNoSelfAdd, ActAddDisabledDate, ActRemoveFromGroup,
		ActAddToGroup, ActAssignPrivilege, ActNotify, ActWebhook}
}

var identityAttributes = []string{"department", "title", "type", "status"}

func (s *Spec) validateConditions() error {
	if len(s.Conditions) > maxConditions {
		return invalid("invalid_conditions", "at most %d conditions", maxConditions)
	}
	for i, c := range s.Conditions {
		bad := func(format string, args ...any) error {
			return invalid("invalid_conditions", "condition %d (%s): "+format, append([]any{i + 1, c.Type}, args...)...)
		}
		want := Condition{Type: c.Type}
		switch c.Type {
		case CondIdentityAttribute:
			if !isMembershipTrigger(s.Trigger) {
				return bad("applies to a membership trigger")
			}
			if !slices.Contains(identityAttributes, c.Attribute) {
				return bad("attribute is one of %s", strings.Join(identityAttributes, ", "))
			}
			if c.Op != "equals" && c.Op != "in" {
				return bad("op is equals or in")
			}
			if len(c.Values) < 1 || len(c.Values) > maxValues || (c.Op == "equals" && len(c.Values) != 1) {
				return bad("equals takes one value, in takes 1 to %d", maxValues)
			}
			for _, v := range c.Values {
				if v == "" || len(v) > maxConditionValueSize {
					return bad("a value is 1 to %d characters", maxConditionValueSize)
				}
			}
			want.Attribute, want.Op, want.Values = c.Attribute, c.Op, c.Values
		case CondIdentityInGroup, CondIdentityNotInGrp:
			if !isMembershipTrigger(s.Trigger) {
				return bad("applies to a membership trigger")
			}
			if err := checkGroupID("group", c.Group); err != nil {
				return err
			}
			want.Group = c.Group
		case CondMembershipSource:
			if s.Trigger != TrigDirectAdded && s.Trigger != TrigDirectRemoved {
				return bad("applies to a direct membership trigger")
			}
			if c.Source == "" || len(c.Source) > 64 {
				return bad("source is 1 to 64 characters")
			}
			want.Source = c.Source
		case CondNameMatches:
			if !isCreateTrigger(s.Trigger) {
				return bad("applies to a creation trigger")
			}
			if _, err := path.Match(c.Pattern, ""); err != nil || c.Pattern == "" || len(c.Pattern) > maxConditionValueSize {
				return bad("pattern is a glob of 1 to %d characters", maxConditionValueSize)
			}
			want.Pattern = c.Pattern
		default:
			return invalid("invalid_conditions", "condition %d: %q is not a condition type", i+1, c.Type)
		}
		if !slices.Equal(want.Values, c.Values) || want.Attribute != c.Attribute || want.Op != c.Op || want.Group != c.Group ||
			want.Source != c.Source || want.Pattern != c.Pattern {
			return bad("takes fields that its type does not use")
		}
	}
	if s.Conditions == nil {
		s.Conditions = []Condition{}
	}
	return nil
}

func (s *Spec) validateAction() error {
	if later, ok := planned[s.Action]; ok {
		return invalid("action_unavailable", "%s arrives with %s", s.Action, later)
	}
	p, want := s.Params, Params{}
	onlyTrigger := func(triggers ...string) error {
		if !slices.Contains(triggers, s.Trigger) {
			return invalid("invalid_trigger", "%s reacts to %s", s.Action, strings.Join(triggers, ", "))
		}
		return nil
	}
	membership := func() error {
		if !isMembershipTrigger(s.Trigger) {
			return invalid("invalid_trigger", "%s reacts to a membership trigger", s.Action)
		}
		return nil
	}
	switch s.Action {
	case ActVeto:
		if err := onlyTrigger(TrigDirectAdded); err != nil {
			return err
		}
		if err := checkText("message", p.Message, maxMessage, true); err != nil {
			return err
		}
		want.Message = p.Message
	case ActRequireMemberOf:
		if err := onlyTrigger(TrigDirectAdded); err != nil {
			return err
		}
		if err := checkGroupID("group", p.Group); err != nil {
			return err
		}
		want.Group = p.Group
		for _, c := range s.Conditions {
			if c.Type == CondMembershipSource {
				return invalid("invalid_conditions", "a membership require rule also removes members, so it takes no membership_source condition")
			}
		}
	case ActOneGroupOnly:
		if err := onlyTrigger(TrigDirectAdded); err != nil {
			return err
		}
		if s.OwnerType != store.RuleOwnerFolder {
			return invalid("invalid_owner", "one group only is a constraint of a folder")
		}
	case ActNoSelfAdd:
		if err := onlyTrigger(TrigDirectAdded); err != nil {
			return err
		}
	case ActAddDisabledDate:
		if err := onlyTrigger(TrigDirectAdded); err != nil {
			return err
		}
		if p.Days < 1 || p.Days > maxDays {
			return invalid("invalid_days", "days is 1 to %d", maxDays)
		}
		want.Days = p.Days
	case ActRemoveFromGroup, ActAddToGroup:
		if err := membership(); err != nil {
			return err
		}
		if err := checkGroupID("group", p.Group); err != nil {
			return err
		}
		want.Group = p.Group
		if s.Action == ActAddToGroup {
			if p.Days < 0 || p.Days > maxDays {
				return invalid("invalid_days", "days is 0 (no end date) to %d", maxDays)
			}
			want.Days = p.Days
		}
	case ActAssignPrivilege:
		if err := onlyTrigger(TrigGroupCreated, TrigFolderCreated); err != nil {
			return err
		}
		if err := s.validatePrivilege(); err != nil {
			return err
		}
		want = Params{Privilege: p.Privilege, HolderType: p.HolderType, HolderIdentity: p.HolderIdentity,
			HolderGroup: p.HolderGroup, AppliesTo: p.AppliesTo, Scope: p.Scope}
	case ActNotify:
		if err := membership(); err != nil {
			return err
		}
		if err := errFirst(checkText("subject", p.Subject, maxName, true), checkText("message", p.Message, maxMessage, true)); err != nil {
			return err
		}
		if p.ToIdentity < 0 {
			return invalid("invalid_to_identity", "to_identity is an identity id")
		}
		want.Subject, want.Message, want.ToIdentity = p.Subject, p.Message, p.ToIdentity
	case ActWebhook:
		if err := checkURL(p.URL); err != nil {
			return err
		}
		if p.Veto && s.Trigger != TrigDirectAdded {
			return invalid("invalid_veto", "only a hook on %s can veto", TrigDirectAdded)
		}
		if p.FailOpen && !p.Veto {
			return invalid("invalid_fail_open", "fail_open belongs to a hook that can veto")
		}
		want.URL, want.Veto, want.FailOpen = p.URL, p.Veto, p.FailOpen
	default:
		return invalid("invalid_action", "%q is not an action (%s)", s.Action, strings.Join(Actions(), ", "))
	}
	if want != p {
		return invalid("invalid_params", "%s takes parameters its action does not use", s.Action)
	}
	return nil
}

func errFirst(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// validatePrivilege checks an assign_privilege action's privilege, holder and
// reach against the kind of object the trigger creates.
func (s *Spec) validatePrivilege() error {
	p := s.Params
	priv := privs.Privilege(p.Privilege)
	if !privs.Valid(priv) {
		return invalid("invalid_privilege", "%q is not a privilege", p.Privilege)
	}
	switch p.HolderType {
	case store.HolderIdentity:
		if p.HolderIdentity < 1 || p.HolderGroup != "" {
			return invalid("invalid_holder", "an identity holder names holder_identity and no holder_group")
		}
	case store.HolderGroup:
		if p.HolderIdentity != 0 {
			return invalid("invalid_holder", "a group holder names holder_group and no holder_identity")
		}
		if err := checkGroupID("holder_group", p.HolderGroup); err != nil {
			return err
		}
	default:
		return invalid("invalid_holder", "a rule assigns a privilege to an identity or a group, never to everyone")
	}
	switch {
	case s.Trigger == TrigGroupCreated:
		if privs.ObjectOf(priv) != privs.Group || p.AppliesTo != "" || p.Scope != "" {
			return invalid("invalid_privilege", "a rule on a new group assigns a group privilege on the group itself")
		}
	case p.AppliesTo == "" || p.AppliesTo == "self":
		if privs.ObjectOf(priv) != privs.Folder || p.Scope != "" {
			return invalid("invalid_privilege", "a rule on a new folder assigns a folder privilege, or an inherited one with applies_to and scope")
		}
	default:
		if (p.Scope != "one" && p.Scope != "sub") || privs.ObjectOf(priv).AppliesTo() != p.AppliesTo {
			return invalid("invalid_privilege", "an inherited privilege names applies_to of its object type and scope one or sub")
		}
	}
	return nil
}

// checkURL checks a webhook URL's shape. The outbound call itself is guarded
// by internal/safehttp (scheme, destination address, redirects).
func checkURL(raw string) error {
	if err := checkText("url", raw, maxURL, true); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Fragment != "" {
		return invalid("invalid_url", "url is an absolute http(s) URL without user info or a fragment")
	}
	return nil
}

// Canonical JSON of a spec's parts, as stored.
func (s *Spec) conditionsJSON() string { return mustJSON(s.Conditions) }
func (s *Spec) paramsJSON() string     { return mustJSON(s.Params) }

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // strings, numbers and booleans
	}
	return string(b)
}
