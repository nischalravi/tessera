package model

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The deletion threshold guard (internal/deleteguard) for groups, folders and direct
// memberships. Every path that deletes one of them asks the guard first, in its own
// transaction; what the guard holds stays as it is and is released later through Release*.

// Item kinds the guard holds for this package.
const (
	ItemGroupDelete = "group_delete" // soft delete of a group
	ItemGroupPurge  = "group_purge"  // purge of a soft-deleted group
	ItemGroupTree   = "group_tree"   // a group of a recursive folder delete: soft delete (if active) and purge
	ItemFolder      = "folder"
	ItemMember      = "member"
)

func groupItem(kind string, g *store.NativeGroup) deleteguard.Item {
	return deleteguard.Item{Kind: kind, Ref: string(g.ID), Label: g.Name}
}

// folderItem sorts deepest first (a folder is removed after what is in it), then by name.
func folderItem(f *store.Folder) deleteguard.Item {
	return deleteguard.Item{Kind: ItemFolder, Ref: fmt.Sprintf("%03d|%s|%s", 999-depth(f.Name), f.Name, f.ID), Label: f.Name}
}

func memberRef(g store.GroupID, typ store.MemberType, key string) string {
	return string(g) + "|" + string(typ) + "|" + key
}

// source says where the operation's deletions come from.
func (e Env) source() (src, id string) {
	switch {
	case e.Cause == store.CauseLoader:
		return deleteguard.SourceLoader, e.CauseRef
	case e.Cause == store.CauseRule:
		return deleteguard.SourceRule, e.CauseRef
	case e.By != nil:
		return deleteguard.SourceUser, e.SourceID
	}
	return deleteguard.SourceSystem, orStr(e.SourceID, e.CauseRef)
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// admit asks the guard about items of a category. With Override it lets everything through.
func (e Env) admit(category string, items ...deleteguard.Item) (*deleteguard.Decision, error) {
	if e.Override {
		return &deleteguard.Decision{Category: category, Attempted: len(items), Applied: items}, nil
	}
	src, id := e.source()
	actor := ""
	if e.By != nil {
		actor = *e.By
	}
	d, err := deleteguard.Admit(e.Tx, e.Now, deleteguard.Request{Category: category, Items: items, Actor: actor, Source: src,
		SourceID: id, Correlation: e.Correlation, SourceDriven: e.Cause == store.CauseLoader})
	if err != nil {
		return nil, err
	}
	e.Held.Add(d)
	return d, nil
}

// guard vets a single item; held says it was held (nothing is to be done).
func (e Env) guard(category string, it deleteguard.Item) (held bool, err error) {
	d, err := e.admit(category, it)
	if err != nil {
		return false, err
	}
	return len(d.Held) > 0, nil
}

// ---------------------------------------------------------------- release

// ReleaseGroup applies a held group item: it deletes (and for group_tree also purges) the group
// again, outside the threshold. It answers like deleteguard.Applier.
func (e Env) ReleaseGroup(it *store.DeletionHoldItem) (outcome, note string, err error) {
	e.Override = true
	id := it.Ref
	if it.Kind == ItemGroupTree {
		id = id[strings.LastIndex(id, "|")+1:]
	}
	g, err := e.Group(store.GroupID(id))
	var me *Error
	if errors.As(err, &me) && me.Kind == NotFound {
		return deleteguard.ItemGone, "the group no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	refuse := func(err error) (string, string, error) {
		if errors.As(err, &me) {
			return deleteguard.ItemFailed, me.Msg, nil
		}
		return "", "", err
	}
	switch it.Kind {
	case ItemGroupDelete:
		if g.Status == store.GroupDeleted {
			return deleteguard.ItemGone, "the group is already deleted", nil
		}
		if err := e.DeleteGroup(g.ID); err != nil {
			return refuse(err)
		}
	case ItemGroupPurge:
		if err := e.PurgeGroup(g.ID); err != nil {
			return refuse(err)
		}
	case ItemGroupTree:
		if g.Status != store.GroupDeleted {
			if err := e.DeleteGroup(g.ID); err != nil {
				return refuse(err)
			}
		}
		if err := e.PurgeGroup(g.ID); err != nil {
			return refuse(err)
		}
	default:
		return "", "", fmt.Errorf("model: %q is not a group item", it.Kind)
	}
	return deleteguard.ItemReleased, "", nil
}

// ReleaseFolder applies a held folder item: the folder is removed if it is still empty.
func (e Env) ReleaseFolder(it *store.DeletionHoldItem) (outcome, note string, err error) {
	parts := strings.SplitN(it.Ref, "|", 3)
	if len(parts) != 3 {
		return "", "", fmt.Errorf("model: bad folder item %q", it.Ref)
	}
	e.Override = true
	f, err := e.Folder(store.FolderID(parts[2]))
	var me *Error
	if errors.As(err, &me) && me.Kind == NotFound {
		return deleteguard.ItemGone, "the folder no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	if err := e.DeleteFolder(f.ID); err != nil {
		if errors.As(err, &me) {
			return deleteguard.ItemFailed, me.Msg, nil
		}
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}

// ReleaseMember applies a held membership removal: it is removed if the membership is still
// there and, for a loader's row, still the loader's.
func (e Env) ReleaseMember(it *store.DeletionHoldItem) (outcome, note string, err error) {
	parts := strings.SplitN(it.Ref, "|", 3)
	if len(parts) != 3 {
		return "", "", fmt.Errorf("model: bad member item %q", it.Ref)
	}
	e.Override = true
	g, err := e.Group(store.GroupID(parts[0]))
	var gone *Error
	if (errors.As(err, &gone) && gone.Kind == NotFound) || (err == nil && g.Status == store.GroupDeleted) {
		return deleteguard.ItemGone, "the group no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	typ := store.MemberType(parts[1])
	m, err := e.Tx.GrpDirectFind(g.ID, store.MembersListID(e.Tx.Tenant()), typ, parts[2])
	if errors.Is(err, store.ErrNotFound) {
		return deleteguard.ItemGone, "the membership no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	if _, err := e.removeRow(g, m, typ, parts[2]); err != nil {
		var me *Error
		if errors.As(err, &me) {
			return deleteguard.ItemFailed, me.Msg, nil
		}
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}
