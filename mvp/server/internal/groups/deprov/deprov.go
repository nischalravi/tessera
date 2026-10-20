// Package deprov is group deprovisioning (design
// docs/design/groups-grouper-parity.md §10.5; issue #57, GR-14). Affiliations
// are reference groups an administrator designates (employee, enrolled student,
// active guest). When an identity leaves every one of them, or is no longer
// active (a leaver), Tessera opens one item and one Inbox task per folder where
// the identity still has direct memberships or privileges. A folder chooses what
// then happens: only notify its owners, remove after N days, or remove at once.
// A built-in rule vetoes new direct memberships for a deprovisioned identity
// unless the actor overrides it with a reason. Automatic removals act with the
// privileges of the user who saved the folder's mode, checked when they fire.
package deprov

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/inbox"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Consumer is the deprovisioning cursor's name in grp_event_cursors.
const Consumer = "deprov"

// MaxAffiliations bounds the designated groups.
const MaxAffiliations = 20

// MaxReason bounds a reason text.
const MaxReason = 1000

// Env is one operation's context. By is the platform user ("" for a job).
type Env struct {
	Tx          *store.TenantTx
	Now         time.Time
	By          string
	ByIdentity  *int64
	TenantAdmin bool
	Checker     *privs.Checker
	Engine      *engine.Engine
}

func (e Env) eng() *engine.Engine {
	if e.Engine != nil {
		return e.Engine
	}
	return engine.New(0)
}

// ---------------------------------------------------------------- settings

// Settings are the tenant's deprovisioning settings.
type Settings struct {
	// Affiliations are the groups that keep an identity eligible.
	Affiliations []string `json:"affiliations"`
	// VetoEnabled makes new direct memberships of deprovisioned identities a 409 (default true).
	VetoEnabled bool       `json:"veto_enabled"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	UpdatedBy   *string    `json:"updated_by,omitempty"`
}

// LoadSettings returns the settings (no affiliations, veto on, while none are saved).
func LoadSettings(tx *store.TenantTx) (Settings, error) {
	r, err := tx.GrpDeprovSettings()
	if errors.Is(err, store.ErrNotFound) {
		return Settings{Affiliations: []string{}, VetoEnabled: true}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	s := Settings{VetoEnabled: r.VetoEnabled, UpdatedAt: &r.UpdatedAt, UpdatedBy: r.UpdatedBy}
	if err := json.Unmarshal([]byte(r.Affiliations), &s.Affiliations); err != nil {
		return Settings{}, err
	}
	if s.Affiliations == nil {
		s.Affiliations = []string{}
	}
	return s, nil
}

// SaveSettings validates and stores the settings: every affiliation is a live group.
func SaveSettings(e Env, in Settings) (Settings, error) {
	if len(in.Affiliations) > MaxAffiliations {
		return Settings{}, gov.Invalid("invalid_affiliations", "at most %d affiliations", MaxAffiliations)
	}
	seen := map[string]bool{}
	for _, id := range in.Affiliations {
		if seen[id] {
			return Settings{}, gov.Invalid("invalid_affiliations", "affiliation %s is listed twice", id)
		}
		seen[id] = true
		g, err := e.Tx.GrpGroup(store.GroupID(id))
		if errors.Is(err, store.ErrNotFound) {
			return Settings{}, gov.Invalid("unknown_group", "no such group: %s", id)
		}
		if err != nil {
			return Settings{}, err
		}
		if g.Status == store.GroupDeleted {
			return Settings{}, gov.Conflict("group_deleted", "group %q is deleted", g.Name)
		}
	}
	aff, err := json.Marshal(in.Affiliations)
	if err != nil {
		return Settings{}, err
	}
	var by *string
	if e.By != "" {
		by = &e.By
	}
	// the first save starts the cursor at the head: affiliation losses of the past are not acted on
	if _, err := e.Tx.GrpDeprovSettings(); errors.Is(err, store.ErrNotFound) {
		head, err := e.Tx.GrpEventHead()
		if err != nil {
			return Settings{}, err
		}
		if err := events.Ack(e.Tx, Consumer, head.LastSeq, e.Now); err != nil {
			return Settings{}, err
		}
	} else if err != nil {
		return Settings{}, err
	}
	if err := e.Tx.SetGrpDeprovSettings(&store.GrpDeprovSettings{Affiliations: string(aff), VetoEnabled: in.VetoEnabled, UpdatedAt: e.Now,
		UpdatedBy: by}); err != nil {
		return Settings{}, err
	}
	if _, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.deprovisioning.settings_saved", LegacyActor: "groups",
		TargetType: "tenant", TargetID: e.Tx.Tenant().String(), Detail: ojson.Object{{Key: "affiliations", Value: in.Affiliations},
			{Key: "veto_enabled", Value: in.VetoEnabled}}}); err != nil {
		return Settings{}, err
	}
	return LoadSettings(e.Tx)
}

// ---------------------------------------------------------------- folder modes

// FolderMode is a folder's deprovisioning choice.
type FolderMode struct {
	Mode          string     `json:"mode"` // notify | auto_after | auto_now
	Days          int        `json:"days"` // auto_after only
	Inherited     bool       `json:"inherited"`
	InheritedFrom string     `json:"inherited_from,omitempty"`
	UpdatedBy     string     `json:"updated_by,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

func chain(tx *store.TenantTx, id store.FolderID) ([]*store.Folder, error) {
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

// ModeOf returns the mode that applies to a folder: its own, else the nearest
// ancestor's, else notify. The stored row is returned too (nil for the default).
func ModeOf(tx *store.TenantTx, folder store.FolderID) (FolderMode, *store.GrpDeprovFolder, error) {
	ch, err := chain(tx, folder)
	if err != nil {
		return FolderMode{}, nil, err
	}
	for i, f := range ch {
		r, err := tx.GrpDeprovFolder(f.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return FolderMode{}, nil, err
		}
		m := FolderMode{Mode: r.Mode, Days: r.Days, UpdatedBy: r.UpdatedBy, UpdatedAt: &r.UpdatedAt}
		if i > 0 {
			m.Inherited, m.InheritedFrom = true, string(f.ID)
		}
		return m, r, nil
	}
	return FolderMode{Mode: store.DeprovNotify}, nil, nil
}

// SetFolder saves a folder's mode. The user needs stem_admin on the folder and
// the mode acts as them from now on.
func SetFolder(e Env, folder store.FolderID, mode string, days int) (FolderMode, error) {
	if e.By == "" {
		return FolderMode{}, gov.Forbidden("settings_need_user", "automatic removal acts with the authority of the user who saves it, so a machine client cannot save it")
	}
	f, err := e.Tx.GrpFolder(folder)
	if errors.Is(err, store.ErrNotFound) {
		return FolderMode{}, gov.NotFound("no such folder")
	}
	if err != nil {
		return FolderMode{}, err
	}
	if f.ManagedBy == store.ManagedByGrouperMirror {
		return FolderMode{}, gov.Conflict("folder_mirrored", "folder %q is mirrored from Grouper and is read-only here", f.Name)
	}
	switch mode {
	case store.DeprovNotify, store.DeprovAutoNow:
		if days != 0 {
			return FolderMode{}, gov.Invalid("invalid_days", "days belongs to auto_after")
		}
	case store.DeprovAutoAfter:
		if days < 1 || days > 3650 {
			return FolderMode{}, gov.Invalid("invalid_days", "days is 1 to 3650")
		}
	default:
		return FolderMode{}, gov.Invalid("invalid_mode", "mode is notify, auto_after or auto_now")
	}
	if err := e.Checker.Require(privs.FolderObject(f.ID), privs.StemAdmin); err != nil {
		return FolderMode{}, err
	}
	if err := e.Tx.SetGrpDeprovFolder(&store.GrpDeprovFolder{FolderID: f.ID, Mode: mode, Days: days, UpdatedBy: e.By, UpdatedAt: e.Now}); err != nil {
		return FolderMode{}, err
	}
	if _, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.deprovisioning.folder_saved", LegacyActor: "groups",
		TargetType: "folder", TargetID: string(f.ID), Detail: ojson.Object{{Key: "folder_id", Value: string(f.ID)}, {Key: "mode", Value: mode},
			{Key: "days", Value: days}}}); err != nil {
		return FolderMode{}, err
	}
	m, _, err := ModeOf(e.Tx, f.ID)
	return m, err
}

// DeleteFolder removes a folder's own mode (it inherits again).
func DeleteFolder(e Env, folder store.FolderID) error {
	if _, err := e.Tx.GrpFolder(folder); errors.Is(err, store.ErrNotFound) {
		return gov.NotFound("no such folder")
	} else if err != nil {
		return err
	}
	if err := e.Checker.Require(privs.FolderObject(folder), privs.StemAdmin); err != nil {
		return err
	}
	had, err := e.Tx.DeleteGrpDeprovFolder(folder)
	if err != nil {
		return err
	}
	if !had {
		return gov.NotFound("this folder has no deprovisioning mode of its own")
	}
	_, err = e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.deprovisioning.folder_deleted", LegacyActor: "groups",
		TargetType: "folder", TargetID: string(folder), Detail: ojson.Object{{Key: "folder_id", Value: string(folder)}}})
	return err
}

// ---------------------------------------------------------------- detecting

// holdings is what an identity still has in one folder.
type holdings struct {
	Groups     []heldGroup `json:"groups"`
	Privileges []heldPriv  `json:"privileges"`
}

type heldGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type heldPriv struct {
	ID         string `json:"id"`
	Privilege  string `json:"privilege"`
	ObjectType string `json:"object_type"`
	ObjectID   string `json:"object_id"`
}

// holdingsByFolder finds the direct memberships and identity-held privileges of
// an identity and groups them by the folder they sit in. The affiliation groups
// themselves are not "held": leaving them is what started this.
func holdingsByFolder(tx *store.TenantTx, now time.Time, identity int64, skip map[string]bool) (map[store.FolderID]*holdings, error) {
	out := map[store.FolderID]*holdings{}
	at := func(f store.FolderID) *holdings {
		if out[f] == nil {
			out[f] = &holdings{Groups: []heldGroup{}, Privileges: []heldPriv{}}
		}
		return out[f]
	}
	ids, err := tx.GrpDirectIdentityGroups(store.MembersListID(tx.Tenant()), identity, now)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if skip[string(id)] {
			continue
		}
		g, err := tx.GrpGroup(id)
		if err != nil {
			return nil, err
		}
		h := at(g.FolderID)
		h.Groups = append(h.Groups, heldGroup{ID: string(g.ID), Name: g.Name})
	}
	rows, err := tx.GrpPrivilegesOfHolderIdentity(identity)
	if err != nil {
		return nil, err
	}
	for _, p := range rows {
		var folder store.FolderID
		switch p.ObjectType {
		case string(privs.Folder):
			folder = store.FolderID(p.ObjectID)
		case string(privs.Group):
			g, err := tx.GrpGroup(store.GroupID(p.ObjectID))
			if errors.Is(err, store.ErrNotFound) || (err == nil && g.Status == store.GroupDeleted) {
				continue
			}
			if err != nil {
				return nil, err
			}
			folder = g.FolderID
		default:
			continue
		}
		h := at(folder)
		h.Privileges = append(h.Privileges, heldPriv{ID: p.ID, Privilege: p.Privilege, ObjectType: p.ObjectType, ObjectID: p.ObjectID})
	}
	return out, nil
}

// Deprovision records that an identity is deprovisioned and opens an item and
// an Inbox task for every folder where it still holds something. Opening twice
// is harmless: a folder with an open item for the identity is left alone. It
// returns how many items it opened.
func Deprovision(e Env, identity int64, reason string) (int, error) {
	set, err := LoadSettings(e.Tx)
	if err != nil {
		return 0, err
	}
	if err := e.Tx.SetGrpDeprovMark(store.GrpDeprovMark{Identity: identity, Since: e.Now, Reason: reason}); err != nil {
		return 0, err
	}
	skip := map[string]bool{}
	for _, a := range set.Affiliations {
		skip[a] = true
	}
	held, err := holdingsByFolder(e.Tx, e.Now, identity, skip)
	if err != nil {
		return 0, err
	}
	folders := make([]store.FolderID, 0, len(held))
	for f := range held {
		folders = append(folders, f)
	}
	slices.Sort(folders)
	opened := 0
	for _, f := range folders {
		h := held[f]
		if len(h.Groups) == 0 && len(h.Privileges) == 0 {
			continue
		}
		cur, err := e.Tx.GrpDeprovItems(store.GrpDeprovFilter{Status: store.DeprovOpen, FolderID: f, Identity: identity, Limit: 1})
		if err != nil {
			return opened, err
		}
		if len(cur) > 0 {
			continue
		}
		mode, _, err := ModeOf(e.Tx, f)
		if err != nil {
			return opened, err
		}
		detail, err := json.Marshal(h)
		if err != nil {
			return opened, err
		}
		item := &store.GrpDeprovItem{Identity: identity, FolderID: f, Mode: mode.Mode, Detail: string(detail), OpenedAt: e.Now}
		if mode.Mode == store.DeprovAutoAfter {
			due := e.Now.AddDate(0, 0, mode.Days)
			item.DueAt = &due
		}
		name := strconv.FormatInt(identity, 10)
		if i, err := e.Tx.Identity(identity); err == nil {
			name = i.Name
		}
		folderName := string(f)
		if fo, err := e.Tx.GrpFolder(f); err == nil {
			folderName = fo.Name
		}
		who := identity
		task, _, err := inbox.Open(e.Tx, e.Now, inbox.Input{Kind: store.TaskDeprovisioning,
			Title:      "Deprovision " + name + " in " + folderName,
			Detail:     map[string]any{"identity": identity, "reason": reason, "mode": mode.Mode, "holdings": h},
			ObjectType: store.RuleOwnerFolder, ObjectID: string(f), Subject: &who, DueAt: item.DueAt,
			DedupeKey: fmt.Sprintf("deprov:%d:%s", identity, f)})
		if err != nil {
			return opened, err
		}
		item.TaskID = &task.ID
		if err := e.Tx.InsertGrpDeprovItem(item); err != nil {
			return opened, err
		}
		opened++
		if _, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.deprovisioning.opened", LegacyActor: "groups",
			TargetType: "deprovisioning", TargetID: item.ID, Detail: ojson.Object{{Key: "item_id", Value: item.ID}, {Key: "identity_id", Value: identity},
				{Key: "folder_id", Value: string(f)}, {Key: "mode", Value: mode.Mode}, {Key: "reason", Value: reason},
				{Key: "groups", Value: len(h.Groups)}, {Key: "privileges", Value: len(h.Privileges)}}}); err != nil {
			return opened, err
		}
		if mode.Mode == store.DeprovAutoNow {
			if err := e.autoRemove(item); err != nil {
				return opened, err
			}
		}
	}
	return opened, nil
}

// Reinstate clears an identity's deprovisioned mark (it regained an affiliation).
func Reinstate(e Env, identity int64) error {
	had, err := e.Tx.ClearGrpDeprovMark(identity)
	if err != nil || !had {
		return err
	}
	_, err = e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.deprovisioning.reinstated", LegacyActor: "groups",
		TargetType: "identity", TargetID: strconv.FormatInt(identity, 10), Detail: ojson.Object{{Key: "identity_id", Value: identity}}})
	return err
}

// stillAffiliated reports whether the identity is in at least one affiliation group.
func (e Env) stillAffiliated(affiliations []string, identity int64) (bool, error) {
	list := store.MembersListID(e.Tx.Tenant())
	for _, a := range affiliations {
		in, err := e.eng().IsMember(e.Tx, e.Now, store.GroupID(a), list, identity)
		if err != nil || in {
			return in, err
		}
	}
	return false, nil
}

// Process reads up to limit group events after the "deprov" cursor: an identity
// that left an affiliation and is in none is deprovisioned, one that joined an
// affiliation is reinstated. It then looks for identities that are no longer
// active (leavers) and still hold memberships. It returns how many events it read.
func Process(e Env, limit int) (int, error) {
	set, err := LoadSettings(e.Tx)
	if err != nil {
		return 0, err
	}
	evs, err := events.Poll(e.Tx, Consumer, limit)
	if err != nil {
		return 0, err
	}
	aff := map[string]bool{}
	for _, a := range set.Affiliations {
		aff[a] = true
	}
	list := string(store.MembersListID(e.Tx.Tenant()))
	for _, ev := range evs {
		if len(aff) == 0 || ev.Identity == nil || ev.List != list || !aff[ev.ObjectID] {
			continue
		}
		switch ev.Type {
		case events.MembershipEffectiveRemoved:
			in, err := e.stillAffiliated(set.Affiliations, *ev.Identity)
			if err != nil {
				return 0, err
			}
			if !in {
				if _, err := Deprovision(e, *ev.Identity, store.DeprovAffiliationLost); err != nil {
					return 0, fmt.Errorf("deprov: event %d: %w", ev.Seq, err)
				}
			}
		case events.MembershipEffectiveAdded:
			if err := Reinstate(e, *ev.Identity); err != nil {
				return 0, err
			}
		}
	}
	if len(evs) > 0 {
		if err := events.Ack(e.Tx, Consumer, evs[len(evs)-1].Seq, e.Now); err != nil {
			return 0, err
		}
	}
	return len(evs), nil
}

// ScanLeavers deprovisions identities that are no longer active and still hold
// a direct membership (a JML leaver, an expired guest).
func ScanLeavers(e Env) (int, error) {
	ids, err := e.Tx.GrpInactiveHolders()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if cur, err := e.Tx.GrpDeprovItems(store.GrpDeprovFilter{Status: store.DeprovOpen, Identity: id, Limit: 1}); err != nil {
			return n, err
		} else if len(cur) > 0 {
			continue
		}
		o, err := Deprovision(e, id, store.DeprovLeaver)
		if err != nil {
			return n, err
		}
		n += o
	}
	return n, nil
}

// ---------------------------------------------------------------- removing

// subjectOf is the privilege subject of a stored user id.
func (e Env) subjectOf(userID string) (privs.Subject, bool, error) {
	s, err := privs.SubjectOfUser(e.Tx, userID, e.Now)
	if errors.Is(err, privs.ErrNoUser) {
		return privs.Subject{}, false, nil
	}
	return s, err == nil, err
}

// removeAs removes what an item lists, as the checker's subject: each direct
// membership needs update on its group, each privilege admin (stem_admin) on its
// object. It reads the memberships back, and reports what was removed and what
// was refused. The item is resolved only when nothing is left.
func (e Env) removeAs(ck *privs.Checker, by string, item *store.GrpDeprovItem) (removed int, refused []string, err error) {
	var h holdings
	if err := json.Unmarshal([]byte(item.Detail), &h); err != nil {
		return 0, nil, err
	}
	me := model.Env{Tx: e.Tx, Now: e.Now, Engine: e.Engine, ByIdentity: ck.Subject().Identity, TenantAdmin: ck.Subject().TenantAdmin,
		Cause: store.CauseEngine, CauseRef: "deprovisioning:" + item.ID}
	if by != "" {
		me.By = &by
	}
	list := store.MembersListID(e.Tx.Tenant())
	for _, g := range h.Groups {
		ok, err := ck.Has(privs.GroupObject(store.GroupID(g.ID)), privs.Update)
		if err != nil {
			return removed, refused, err
		}
		if !ok {
			refused = append(refused, g.Name+": privilege_required: update")
			continue
		}
		_, err = me.RemoveMember(store.GroupID(g.ID), strconv.FormatInt(item.Identity, 10))
		var mErr *model.Error
		switch {
		case errors.As(err, &mErr) && mErr.Kind == model.NotFound:
			continue // already gone
		case errors.As(err, &mErr):
			refused = append(refused, g.Name+": "+mErr.Code)
			continue
		case err != nil:
			return removed, refused, err
		}
		// read it back
		if _, err := e.Tx.GrpDirectFind(store.GroupID(g.ID), list, store.MemberIdentity, strconv.FormatInt(item.Identity, 10)); err == nil {
			refused = append(refused, g.Name+": still a member after the removal")
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return removed, refused, err
		}
		removed++
	}
	pe := privs.Env{Tx: e.Tx, Now: e.Now, ByIdentity: ck.Subject().Identity, TenantAdmin: ck.Subject().TenantAdmin}
	if by != "" {
		pe.By = &by
	}
	for _, p := range h.Privileges {
		obj := privs.Object{Type: privs.ObjectType(p.ObjectType), ID: p.ObjectID}
		need := privs.Admin
		if obj.Type == privs.Folder {
			need = privs.StemAdmin
		}
		if ok, err := ck.Has(obj, need); err != nil {
			return removed, refused, err
		} else if !ok {
			refused = append(refused, p.Privilege+" on "+p.ObjectType+": privilege_required: "+string(need))
			continue
		}
		if _, err := privs.Revoke(pe, p.ID); err != nil {
			var perr *privs.Error
			if errors.As(err, &perr) && perr.Kind == privs.NotFound {
				continue // already revoked
			}
			if errors.As(err, &perr) {
				refused = append(refused, p.Privilege+" on "+p.ObjectType+": "+perr.Code)
				continue
			}
			return removed, refused, err
		}
		removed++
	}
	return removed, refused, nil
}

// finish resolves an item after a removal attempt and closes its task.
func (e Env) finish(item *store.GrpDeprovItem, removed int, refused []string, by, how string) error {
	d := ojson.Object{{Key: "item_id", Value: item.ID}, {Key: "identity_id", Value: item.Identity}, {Key: "folder_id", Value: string(item.FolderID)},
		{Key: "removed", Value: removed}, {Key: "refused", Value: refused}, {Key: "how", Value: how}}
	if len(refused) > 0 {
		_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.deprovisioning.removal_partial", LegacyActor: "groups",
			TargetType: "deprovisioning", TargetID: item.ID, Detail: d})
		return err // stays open: the folder's owners finish it
	}
	if err := e.Tx.ResolveGrpDeprovItem(item.ID, store.DeprovRemoved, by, how, e.Now); err != nil {
		return err
	}
	if item.TaskID != nil {
		if err := inbox.CloseSystem(e.Tx, e.Now, *item.TaskID, store.TaskDone, by); err != nil {
			return err
		}
	}
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.deprovisioning.removed", LegacyActor: "groups",
		TargetType: "deprovisioning", TargetID: item.ID, Detail: d})
	return err
}

// autoRemove removes an item's holdings as the user who saved the folder's mode,
// with what they hold now. When they hold too little, or are gone, nothing is
// removed and the item stays open for the folder's owners.
func (e Env) autoRemove(item *store.GrpDeprovItem) error {
	_, row, err := ModeOf(e.Tx, item.FolderID)
	if err != nil {
		return err
	}
	if row == nil {
		return nil
	}
	sub, ok, err := e.subjectOf(row.UpdatedBy)
	if err != nil || !ok {
		return err
	}
	ck := privs.NewChecker(e.Tx, e.Now, e.eng(), sub)
	removed, refused, err := e.removeAs(ck, row.UpdatedBy, item)
	if err != nil {
		return err
	}
	return e.finish(item, removed, refused, row.UpdatedBy, "automatic ("+item.Mode+")")
}

// Sweep removes the holdings of the open items whose delay has run out.
func Sweep(e Env) (int, error) {
	items, err := e.Tx.GrpDeprovItems(store.GrpDeprovFilter{Status: store.DeprovOpen, Limit: 1000})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if it.Mode != store.DeprovAutoAfter || it.DueAt == nil || e.Now.Before(*it.DueAt) {
			continue
		}
		if err := e.autoRemove(it); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Resolve settles an item by hand. remove carries out the removal with the
// caller's privileges; dismiss closes it with a reason (the identity keeps
// what it holds). The caller needs stem_admin on the item's folder.
func Resolve(e Env, id, action, reason string) (*store.GrpDeprovItem, error) {
	item, err := e.Tx.GrpDeprovItem(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, gov.NotFound("no such deprovisioning item")
	}
	if err != nil {
		return nil, err
	}
	if err := e.Checker.Require(privs.FolderObject(item.FolderID), privs.StemAdmin); err != nil {
		return nil, err
	}
	if item.Status != store.DeprovOpen {
		return nil, gov.Conflict("item_closed", "the item is already %s", item.Status)
	}
	if len(reason) > MaxReason {
		return nil, gov.Invalid("invalid_reason", "reason is at most %d characters", MaxReason)
	}
	switch action {
	case "remove":
		removed, refused, err := e.removeAs(e.Checker, e.By, item)
		if err != nil {
			return nil, err
		}
		if len(refused) > 0 {
			if err := e.finish(item, removed, refused, e.By, "manual"); err != nil {
				return nil, err
			}
			return nil, &gov.Error{Kind: gov.KindForbidden, Code: "removal_incomplete", Msg: "some holdings could not be removed with your privileges",
				Extra: map[string]any{"removed": removed, "refused": refused}}
		}
		if err := e.finish(item, removed, nil, e.By, "manual"); err != nil {
			return nil, err
		}
	case "dismiss":
		if reason == "" {
			return nil, gov.Invalid("reason_required", "dismissing needs a reason")
		}
		if err := e.Tx.ResolveGrpDeprovItem(item.ID, store.DeprovDismissed, e.By, reason, e.Now); err != nil {
			return nil, err
		}
		if item.TaskID != nil {
			if err := inbox.CloseSystem(e.Tx, e.Now, *item.TaskID, store.TaskDismissed, e.By); err != nil {
				return nil, err
			}
		}
		if _, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.deprovisioning.dismissed", LegacyActor: "groups",
			TargetType: "deprovisioning", TargetID: item.ID, Detail: ojson.Object{{Key: "item_id", Value: item.ID},
				{Key: "identity_id", Value: item.Identity}, {Key: "folder_id", Value: string(item.FolderID)}, {Key: "reason", Value: reason}}}); err != nil {
			return nil, err
		}
	default:
		return nil, gov.Invalid("invalid_action", "action is remove or dismiss")
	}
	return e.Tx.GrpDeprovItem(item.ID)
}

// ItemView is an item as the API shows it.
type ItemView struct {
	ID           string          `json:"id"`
	Identity     int64           `json:"identity_id"`
	IdentityName string          `json:"identity_name,omitempty"`
	FolderID     string          `json:"folder_id"`
	FolderName   string          `json:"folder_name,omitempty"`
	Status       string          `json:"status"`
	Mode         string          `json:"mode"`
	Holdings     json.RawMessage `json:"holdings"`
	OpenedAt     time.Time       `json:"opened_at"`
	DueAt        *time.Time      `json:"due_at,omitempty"`
	ResolvedAt   *time.Time      `json:"resolved_at,omitempty"`
	ResolvedBy   *string         `json:"resolved_by,omitempty"`
	Reason       string          `json:"reason,omitempty"`
}

// ViewOf renders an item.
func ViewOf(tx *store.TenantTx, it *store.GrpDeprovItem) ItemView {
	v := ItemView{ID: it.ID, Identity: it.Identity, FolderID: string(it.FolderID), Status: it.Status, Mode: it.Mode,
		Holdings: json.RawMessage(it.Detail), OpenedAt: it.OpenedAt, DueAt: it.DueAt, ResolvedAt: it.ResolvedAt, ResolvedBy: it.ResolvedBy,
		Reason: it.Reason}
	if i, err := tx.Identity(it.Identity); err == nil {
		v.IdentityName = i.Name
	}
	if f, err := tx.GrpFolder(it.FolderID); err == nil {
		v.FolderName = f.Name
	}
	return v
}

// List returns a page of the items in folders the subject administers
// (stem_admin), oldest first: an item names a person, so one in a folder the
// subject does not administer is not shown.
func List(tx *store.TenantTx, ck *privs.Checker, f store.GrpDeprovFilter, limit, offset int) ([]ItemView, error) {
	if limit < 1 {
		limit = 100
	}
	const chunk = 500
	out := []ItemView{}
	skip := offset
	for raw := 0; len(out) < limit; raw += chunk {
		f.Limit, f.Offset = chunk, raw
		rows, err := tx.GrpDeprovItems(f)
		if err != nil {
			return nil, err
		}
		for _, it := range rows {
			ok, err := ck.Has(privs.FolderObject(it.FolderID), privs.StemAdmin)
			if err != nil {
				return nil, err
			}
			switch {
			case !ok:
			case skip > 0:
				skip--
			case len(out) < limit:
				out = append(out, ViewOf(tx, it))
			}
		}
		if len(rows) < chunk {
			break
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- the veto rule

// Vetoed is the built-in rule that refuses a new direct membership for a
// deprovisioned identity (Grouper's MembershipVetoIfDeprovisionedHook). It
// returns the refusal's message, or "" when the add may go on. A non-empty
// override (a reason an administrator gave) lets it through and is audited.
func Vetoed(tx *store.TenantTx, now time.Time, g *store.NativeGroup, identity int64, override string) (string, error) {
	set, err := LoadSettings(tx)
	if err != nil || !set.VetoEnabled || len(set.Affiliations) == 0 {
		return "", err
	}
	// joining an affiliation is how an identity stops being deprovisioned
	if slices.Contains(set.Affiliations, string(g.ID)) {
		return "", nil
	}
	mark, err := tx.GrpDeprovMark(identity)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if override != "" {
		_, err := tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.deprovisioning.veto_overridden", LegacyActor: "groups",
			TargetType: "group", TargetID: string(g.ID), Detail: ojson.Object{{Key: "group_id", Value: string(g.ID)}, {Key: "identity_id", Value: identity},
				{Key: "reason", Value: override}}})
		return "", err
	}
	return fmt.Sprintf("identity %d was deprovisioned on %s (%s) and cannot be added to %s without an override reason",
		identity, mark.Since.UTC().Format("2006-01-02"), mark.Reason, g.Name), nil
}
