// Package ownership assigns owners to applications, entitlements (groups),
// resources and machine identities (issue #167).
//
// Each object has a primary owner and an optional backup owner (both active
// people), an optional owner group, and a purpose. For a machine identity
// the primary owner is also its identities.owner_id, which the NHI
// inventory, policies, reviews and the leaver plan already read; connector
// sync keeps an owner set here (ingest). When an owner leaves, the leaver
// plan promotes the backup, or hands the object to the leaver's manager.
package ownership

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Kinds are the object kinds that can be owned.
var Kinds = []string{store.OwnedApp, store.OwnedGroup, store.OwnedResource, store.OwnedIdentity}

// MaxPurpose caps a purpose.
const MaxPurpose = 500

// MaxBulk caps one bulk assignment.
const MaxBulk = 500

// Error is a refused change; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Ref names an object.
type Ref struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

// Spec is the ownership to set.
type Spec struct {
	PrimaryID *int64
	BackupID  *int64
	GroupID   *int64
	Purpose   string
}

// Entry is one object with its label and ownership.
type Entry struct {
	Ref
	Label     string
	Ownership *store.Ownership // nil: no row (an identity may still have an owner from its connector)
	PrimaryID *int64           // effective primary owner
}

// Label returns an object's display name, or a not_found error.
func Label(tx *store.TenantTx, r Ref) (string, error) {
	missing := refuse(404, "object_not_found", "%s %s not found", r.Kind, r.Key)
	switch r.Kind {
	case store.OwnedApp:
		systems, err := Systems(tx)
		if err != nil {
			return "", err
		}
		if !slices.Contains(systems, r.Key) {
			return "", missing
		}
		return r.Key, nil
	case store.OwnedGroup, store.OwnedResource, store.OwnedIdentity:
		id, err := strconv.ParseInt(r.Key, 10, 64)
		if err != nil {
			return "", missing
		}
		switch r.Kind {
		case store.OwnedGroup:
			g, err := tx.Group(id)
			if errors.Is(err, store.ErrNotFound) {
				return "", missing
			}
			if err != nil {
				return "", err
			}
			return g.System + ":" + g.Name, nil
		case store.OwnedResource:
			n, err := tx.ResourceName(id)
			if errors.Is(err, store.ErrNotFound) {
				return "", missing
			}
			return n, err
		default:
			i, err := tx.Identity(id)
			if errors.Is(err, store.ErrNotFound) {
				return "", missing
			}
			if err != nil {
				return "", err
			}
			if i.Type == "human" {
				return "", refuse(422, "person_not_ownable", "people have managers, not owners")
			}
			return i.Name, nil
		}
	}
	return "", refuse(422, "invalid_kind", "kind is app, group, resource or identity")
}

// Systems lists the applications (systems with accounts, groups or resources).
func Systems(tx *store.TenantTx) ([]string, error) {
	seen := map[string]bool{}
	accts, err := tx.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		seen[a.System] = true
	}
	groups, err := tx.Groups()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		seen[g.System] = true
	}
	res, err := tx.Resources()
	if err != nil {
		return nil, err
	}
	for _, r := range res {
		seen[r.System] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	slices.Sort(out)
	return out, nil
}

func person(tx *store.TenantTx, id *int64, role string) error {
	if id == nil {
		return nil
	}
	i, err := tx.Identity(*id)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, role+"_not_found", "the %s owner was not found", role)
	} else if err != nil {
		return err
	}
	if i.Type != "human" || i.Status != "active" {
		return refuse(409, role+"_not_active", "the %s owner must be an active person", role)
	}
	return nil
}

func (s Spec) check(tx *store.TenantTx) error {
	if len(strings.TrimSpace(s.Purpose)) > MaxPurpose {
		return refuse(422, "invalid_purpose", "the purpose is at most %d characters", MaxPurpose)
	}
	if s.PrimaryID != nil && s.BackupID != nil && *s.PrimaryID == *s.BackupID {
		return refuse(422, "same_owner", "the backup owner must be someone else")
	}
	if s.BackupID != nil && s.PrimaryID == nil {
		return refuse(422, "backup_without_primary", "set a primary owner before a backup")
	}
	if err := person(tx, s.PrimaryID, "primary"); err != nil {
		return err
	}
	if err := person(tx, s.BackupID, "backup"); err != nil {
		return err
	}
	if s.GroupID != nil {
		if _, err := tx.Group(*s.GroupID); errors.Is(err, store.ErrNotFound) {
			return refuse(404, "group_not_found", "the owner group was not found")
		} else if err != nil {
			return err
		}
	}
	return nil
}

// Set replaces one object's ownership.
func Set(tx *store.TenantTx, r Ref, s Spec, actor string, actorUser *string, now time.Time) (*store.Ownership, error) {
	label, err := Label(tx, r)
	if err != nil {
		return nil, err
	}
	if err := s.check(tx); err != nil {
		return nil, err
	}
	return put(tx, r, label, s, actor, actorUser, now)
}

func put(tx *store.TenantTx, r Ref, label string, s Spec, actor string, actorUser *string, now time.Time) (*store.Ownership, error) {
	prev, err := tx.Ownership(r.Kind, r.Key)
	if errors.Is(err, store.ErrNotFound) {
		prev = nil
	} else if err != nil {
		return nil, err
	}
	o := &store.Ownership{Kind: r.Kind, Key: r.Key, PrimaryID: s.PrimaryID, BackupID: s.BackupID, GroupID: s.GroupID,
		Purpose: strings.TrimSpace(s.Purpose), UpdatedBy: actorUser, UpdatedAt: now}
	if err := tx.PutOwnership(o); err != nil {
		return nil, err
	}
	if r.Kind == store.OwnedIdentity {
		id, _ := strconv.ParseInt(r.Key, 10, 64)
		if err := tx.SetIdentityOwner(id, s.PrimaryID); err != nil {
			return nil, err
		}
	}
	det := ojson.Object{{Key: "kind", Value: r.Kind}, {Key: "key", Value: r.Key}, {Key: "object", Value: label},
		{Key: "primary_owner_id", Value: s.PrimaryID}, {Key: "backup_owner_id", Value: s.BackupID},
		{Key: "owner_group_id", Value: s.GroupID}}
	if prev != nil {
		det = append(det, ojson.KV{Key: "previous_primary_owner_id", Value: prev.PrimaryID})
	}
	return o, tx.Audit(now, actor, "ownership.set", det)
}

// SetMany gives several objects the same owners, all or none. The purpose of
// each object is kept unless keepPurpose is false.
func SetMany(tx *store.TenantTx, refs []Ref, s Spec, keepPurpose bool, actor string, actorUser *string, now time.Time) (int, error) {
	if len(refs) == 0 || len(refs) > MaxBulk {
		return 0, refuse(422, "invalid_bulk", "assign 1 to %d objects at a time", MaxBulk)
	}
	if err := s.check(tx); err != nil {
		return 0, err
	}
	seen := map[Ref]bool{}
	n := 0
	for _, r := range refs {
		if seen[r] {
			continue
		}
		seen[r] = true
		label, err := Label(tx, r)
		if err != nil {
			return 0, err
		}
		each := s
		if keepPurpose {
			if old, err := tx.Ownership(r.Kind, r.Key); err == nil {
				each.Purpose = old.Purpose
			} else if !errors.Is(err, store.ErrNotFound) {
				return 0, err
			}
		}
		if _, err := put(tx, r, label, each, actor, actorUser, now); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

// List returns every object of a kind with its ownership.
func List(tx *store.TenantTx, kind string) ([]Entry, error) {
	rows, err := tx.Ownerships(kind)
	if err != nil {
		return nil, err
	}
	byKey := map[string]*store.Ownership{}
	for _, o := range rows {
		byKey[o.Key] = o
	}
	var out []Entry
	add := func(key, label string, connectorOwner *int64) {
		e := Entry{Ref: Ref{kind, key}, Label: label, Ownership: byKey[key], PrimaryID: connectorOwner}
		if e.Ownership != nil {
			e.PrimaryID = e.Ownership.PrimaryID
		}
		out = append(out, e)
	}
	switch kind {
	case store.OwnedApp:
		systems, err := Systems(tx)
		if err != nil {
			return nil, err
		}
		for _, s := range systems {
			add(s, s, nil)
		}
	case store.OwnedGroup:
		gs, err := tx.Groups()
		if err != nil {
			return nil, err
		}
		for _, g := range gs {
			add(strconv.FormatInt(g.ID, 10), g.System+":"+g.Name, nil)
		}
	case store.OwnedResource:
		rs, err := tx.Resources()
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			add(strconv.FormatInt(r.ID, 10), r.Name, nil)
		}
	case store.OwnedIdentity:
		is, err := tx.Identities()
		if err != nil {
			return nil, err
		}
		for _, i := range is {
			if i.Type != "human" {
				add(strconv.FormatInt(i.ID, 10), i.Name, i.OwnerID)
			}
		}
	default:
		return nil, refuse(422, "invalid_kind", "kind is app, group, resource or identity")
	}
	return out, nil
}
