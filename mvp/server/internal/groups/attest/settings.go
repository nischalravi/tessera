// Package attest is group attestation (design
// docs/design/groups-grouper-parity.md §10.4; issue #57, GR-14): the owners of
// a group periodically vouch for its members. An attestation is a group
// membership campaign of the certification engine (internal/reviews), so it
// inherits its items, decisions and audit, and its population is frozen when it
// starts: the identities that were members then, counted and hashed, whatever
// changes while the campaign is open.
//
// Settings on a group or folder (a group takes its nearest folder's) give the
// interval, the window reviewers have, who the reviewers are (the group's
// admins, or a named group), reminders, and what happens when the window ends
// with members unattested: nothing, disable the group, or remove the
// unattested members. Removals go through the membership engine and are read
// back before they count as done. The overdue action acts with the privileges
// of the user who saved the settings, checked again when it fires.
package attest

import (
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits.
const (
	MaxInterval   = 3650
	MaxWindow     = 365
	MaxReminders  = 10
	MaxPopulation = 20000
	// MaxStartsPerPass bounds the campaigns one scheduler pass starts per tenant.
	MaxStartsPerPass = 50
	// MaxReviewerTasks bounds the Inbox tasks made for a reviewer group's members.
	MaxReviewerTasks = 100
)

// Env is one operation's context: the transaction, the clock, who acts and
// what they hold. By is the platform user ("" for a job); Checker answers for
// the acting subject.
type Env struct {
	Tx          *store.TenantTx
	Now         time.Time
	By          string
	ByIdentity  *int64
	TenantAdmin bool
	Checker     *privs.Checker
	Engine      *engine.Engine
	// Cause is the cause type of the events written (default api; jobs say engine).
	Cause    string
	CauseRef string
}

func (e Env) cause() string {
	if e.Cause != "" {
		return e.Cause
	}
	return store.CauseAPI
}

func (e Env) model() model.Env {
	me := model.Env{Tx: e.Tx, Now: e.Now, Engine: e.Engine, ByIdentity: e.ByIdentity, TenantAdmin: e.TenantAdmin, Cause: e.cause(),
		CauseRef: e.CauseRef}
	if e.By != "" {
		by := e.By
		me.By = &by
	}
	return me
}

// Settings is what a client saves.
type Settings struct {
	IntervalDays  int    `json:"interval_days"`
	WindowDays    int    `json:"window_days"`
	Reviewers     string `json:"reviewers"`                // admins | group
	ReviewerGroup string `json:"reviewer_group,omitempty"` // the group when reviewers is group
	// ReminderDays are days before the due date, for example [7, 1].
	ReminderDays  []int  `json:"reminder_days"`
	OverdueAction string `json:"overdue_action"` // none | disable_group | remove_unattested
	Enabled       bool   `json:"enabled"`
}

// View is settings as the API shows them. Configured is false when neither the
// owner nor an ancestor has any; Inherited says they come from InheritedFrom.
type View struct {
	Configured    bool   `json:"configured"`
	Inherited     bool   `json:"inherited"`
	InheritedFrom string `json:"inherited_from,omitempty"` // folder id
	OwnerType     string `json:"owner_type"`
	OwnerID       string `json:"owner_id"`
	Settings
	UpdatedBy string     `json:"updated_by,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func (s *Settings) validate() error {
	if s.IntervalDays < 1 || s.IntervalDays > MaxInterval {
		return gov.Invalid("invalid_interval", "interval_days is 1 to %d", MaxInterval)
	}
	if s.WindowDays < 1 || s.WindowDays > MaxWindow {
		return gov.Invalid("invalid_window", "window_days is 1 to %d", MaxWindow)
	}
	switch s.Reviewers {
	case store.ReviewersAdmins:
		if s.ReviewerGroup != "" {
			return gov.Invalid("invalid_reviewers", "reviewer_group belongs to reviewers group")
		}
	case store.ReviewersGroup:
		if s.ReviewerGroup == "" {
			return gov.Invalid("invalid_reviewers", "reviewers group names reviewer_group")
		}
	default:
		return gov.Invalid("invalid_reviewers", "reviewers is admins or group")
	}
	switch s.OverdueAction {
	case store.OverdueNone, store.OverdueDisable, store.OverdueRemove:
	default:
		return gov.Invalid("invalid_overdue_action", "overdue_action is none, disable_group or remove_unattested")
	}
	if len(s.ReminderDays) > MaxReminders {
		return gov.Invalid("invalid_reminders", "at most %d reminders", MaxReminders)
	}
	seen := map[int]bool{}
	for _, d := range s.ReminderDays {
		if d < 1 || d > s.WindowDays || seen[d] {
			return gov.Invalid("invalid_reminders", "reminder_days are distinct days from 1 to window_days")
		}
		seen[d] = true
	}
	slices.SortFunc(s.ReminderDays, func(a, b int) int { return b - a })
	if s.ReminderDays == nil {
		s.ReminderDays = []int{}
	}
	return nil
}

func viewOf(r *store.GrpAttestSettings) (*View, error) {
	var days []int
	if err := json.Unmarshal([]byte(r.ReminderDays), &days); err != nil {
		return nil, err
	}
	if days == nil {
		days = []int{}
	}
	s := Settings{IntervalDays: r.IntervalDays, WindowDays: r.WindowDays, Reviewers: r.ReviewerType, ReminderDays: days,
		OverdueAction: r.OverdueAction, Enabled: r.Enabled}
	if r.ReviewerGroup != nil {
		s.ReviewerGroup = string(*r.ReviewerGroup)
	}
	return &View{Configured: true, OwnerType: r.OwnerType, OwnerID: r.OwnerID, Settings: s, UpdatedBy: r.UpdatedBy, UpdatedAt: &r.UpdatedAt}, nil
}

// folderChain returns the folder and its ancestors, nearest first.
func folderChain(tx *store.TenantTx, id store.FolderID) ([]*store.Folder, error) {
	var out []*store.Folder
	for cur := &id; cur != nil && len(out) < 256; {
		f, err := tx.GrpFolder(*cur)
		if errors.Is(err, store.ErrNotFound) {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, f)
		cur = f.ParentID
	}
	return out, nil
}

// effective returns the settings that apply to an owner: its own, else the
// nearest ancestor folder's. ok is false when there are none.
func effective(tx *store.TenantTx, ownerType, ownerID string) (r *store.GrpAttestSettings, own bool, ok bool, err error) {
	var start store.FolderID
	switch ownerType {
	case store.RuleOwnerGroup:
		s, err := tx.GrpAttestSettingsOf(ownerType, ownerID)
		if err == nil {
			return s, true, true, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, false, false, err
		}
		g, err := tx.GrpGroup(store.GroupID(ownerID))
		if errors.Is(err, store.ErrNotFound) {
			return nil, false, false, nil
		}
		if err != nil {
			return nil, false, false, err
		}
		start = g.FolderID
	default:
		start = store.FolderID(ownerID)
	}
	chain, err := folderChain(tx, start)
	if err != nil {
		return nil, false, false, err
	}
	for i, f := range chain {
		s, err := tx.GrpAttestSettingsOf(store.RuleOwnerFolder, string(f.ID))
		if err == nil {
			return s, ownerType == store.RuleOwnerFolder && i == 0, true, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, false, false, err
		}
	}
	return nil, false, false, nil
}

// Get returns the settings that apply to a folder or group.
func Get(tx *store.TenantTx, ownerType, ownerID string) (*View, error) {
	r, own, ok, err := effective(tx, ownerType, ownerID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return &View{OwnerType: ownerType, OwnerID: ownerID, Settings: Settings{ReminderDays: []int{}, Reviewers: store.ReviewersAdmins,
			OverdueAction: store.OverdueNone}}, nil
	}
	v, err := viewOf(r)
	if err != nil {
		return nil, err
	}
	v.OwnerType, v.OwnerID = ownerType, ownerID
	if !own {
		v.Inherited, v.InheritedFrom = true, r.OwnerID
	}
	return v, nil
}

// owner checks the owner exists, is live and is not mirrored (K11).
func (e Env) owner(ownerType, ownerID string) error {
	switch ownerType {
	case store.RuleOwnerFolder:
		f, err := e.Tx.GrpFolder(store.FolderID(ownerID))
		if errors.Is(err, store.ErrNotFound) {
			return gov.NotFound("no such folder")
		}
		if err != nil {
			return err
		}
		if f.ManagedBy == store.ManagedByGrouperMirror {
			return gov.Conflict("folder_mirrored", "folder %q is mirrored from Grouper and is read-only here", f.Name)
		}
	case store.RuleOwnerGroup:
		g, err := e.Tx.GrpGroup(store.GroupID(ownerID))
		if errors.Is(err, store.ErrNotFound) {
			return gov.NotFound("no such group")
		}
		if err != nil {
			return err
		}
		if g.Status == store.GroupDeleted {
			return gov.Conflict("group_deleted", "group %q is deleted", g.Name)
		}
		if g.ManagedBy == store.ManagedByGrouperMirror {
			return gov.Conflict("folder_mirrored", "group %q is mirrored from Grouper and is read-only here", g.Name)
		}
	}
	return nil
}

// ownerObject is the privilege object of an owner and the privilege that administers it.
func ownerObject(ownerType, ownerID string) (privs.Object, privs.Privilege) {
	if ownerType == store.RuleOwnerFolder {
		return privs.Object{Type: privs.Folder, ID: ownerID}, privs.StemAdmin
	}
	return privs.Object{Type: privs.Group, ID: ownerID}, privs.Admin
}

// Put saves an owner's settings. The saving user must administer the owner and
// see the reviewer group. The overdue action acts as this user from now on, and
// the privilege it needs on each group is checked when it fires.
func Put(e Env, ownerType, ownerID string, in Settings) (*View, error) {
	if e.By == "" {
		return nil, gov.Forbidden("settings_need_user", "attestation acts with the authority of the user who saves it, so a machine client cannot save settings")
	}
	if err := e.owner(ownerType, ownerID); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	obj, admin := ownerObject(ownerType, ownerID)
	if err := e.Checker.Require(obj, admin); err != nil {
		return nil, err
	}
	var reviewer *store.GroupID
	if in.Reviewers == store.ReviewersGroup {
		g, err := e.Tx.GrpGroup(store.GroupID(in.ReviewerGroup))
		if errors.Is(err, store.ErrNotFound) {
			return nil, gov.Invalid("unknown_group", "no such group: %s", in.ReviewerGroup)
		}
		if err != nil {
			return nil, err
		}
		if g.Status == store.GroupDeleted {
			return nil, gov.Conflict("group_deleted", "group %q is deleted", g.Name)
		}
		if err := e.Checker.Require(privs.GroupObject(g.ID), privs.View); err != nil {
			return nil, err
		}
		reviewer = &g.ID
	}
	r := &store.GrpAttestSettings{OwnerType: ownerType, OwnerID: ownerID, IntervalDays: in.IntervalDays, WindowDays: in.WindowDays,
		ReviewerType: in.Reviewers, ReviewerGroup: reviewer, ReminderDays: mustJSON(in.ReminderDays), OverdueAction: in.OverdueAction,
		Enabled: in.Enabled, UpdatedBy: e.By, UpdatedAt: e.Now}
	if err := e.Tx.SetGrpAttestSettings(r); err != nil {
		return nil, err
	}
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.attestation.settings_saved", LegacyActor: "groups",
		TargetType: ownerType, TargetID: ownerID, Detail: ojson.Object{{Key: "owner_type", Value: ownerType}, {Key: "owner_id", Value: ownerID},
			{Key: "interval_days", Value: in.IntervalDays}, {Key: "window_days", Value: in.WindowDays}, {Key: "reviewers", Value: in.Reviewers},
			{Key: "overdue_action", Value: in.OverdueAction}, {Key: "enabled", Value: in.Enabled}}})
	if err != nil {
		return nil, err
	}
	return Get(e.Tx, ownerType, ownerID)
}

// Delete removes an owner's own settings (it inherits again). It needs admin
// on the owner only: it takes authority away.
func Delete(e Env, ownerType, ownerID string) error {
	if err := e.owner(ownerType, ownerID); err != nil {
		return err
	}
	obj, admin := ownerObject(ownerType, ownerID)
	if err := e.Checker.Require(obj, admin); err != nil {
		return err
	}
	had, err := e.Tx.DeleteGrpAttestSettings(ownerType, ownerID)
	if err != nil {
		return err
	}
	if !had {
		return gov.NotFound("this %s has no attestation settings of its own", ownerType)
	}
	_, err = e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.attestation.settings_deleted", LegacyActor: "groups",
		TargetType: ownerType, TargetID: ownerID, Detail: ojson.Object{{Key: "owner_type", Value: ownerType}, {Key: "owner_id", Value: ownerID}}})
	return err
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // ints and strings
	}
	return string(b)
}
