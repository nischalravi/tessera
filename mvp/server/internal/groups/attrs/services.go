package attrs

import (
	"errors"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Services (G-48, design §10.9): a folder with the object type service appears
// under My access, "Services I can use", with the policy groups below it that
// the person belongs to, which are what grant it.

// typedOwners returns the ids of the owners of a type that carry an object
// type, as a set.
func typedOwners(tx *store.TenantTx, ownerType, objectType string) (map[string]bool, error) {
	_, n, err := Builtin(tx)
	if err != nil || n == nil {
		return nil, err
	}
	as, err := tx.GrpAttrAssignsByValue(n.ID, ownerType, "s:"+objectType)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(as))
	for _, a := range as {
		out[a.OwnerID] = true
	}
	return out, nil
}

// PolicyGroupsBelow lists the live groups with the policy object type below a
// folder (in it and in the folders under it).
func PolicyGroupsBelow(tx *store.TenantTx, f *store.Folder) ([]*store.NativeGroup, error) {
	policy, err := typedOwners(tx, store.AttrOwnerGroup, TypePolicy)
	if err != nil || len(policy) == 0 {
		return nil, err
	}
	below, err := tx.GrpGroupsBelow(f.Name)
	if err != nil {
		return nil, err
	}
	var out []*store.NativeGroup
	for _, g := range below {
		if policy[string(g.ID)] && g.Status != store.GroupDeleted {
			out = append(out, g)
		}
	}
	return out, nil
}

// Service is a service folder and the policy groups under it that grant it to
// the person.
type Service struct {
	Folder *store.Folder
	Groups []*store.NativeGroup
}

// ServicesFor lists the services the identity can use: the service folders the
// caller may view, each with the policy groups below it that the caller may view
// and the identity is an effective member of. A service that grants the identity
// nothing is not listed.
func ServicesFor(ck *privs.Checker, tx *store.TenantTx, eng *engine.Engine, now time.Time, identity int64) ([]Service, error) {
	owners, err := typedOwners(tx, store.AttrOwnerFolder, TypeService)
	if err != nil || len(owners) == 0 {
		return nil, err
	}
	if eng == nil {
		eng = engine.New(0)
	}
	ids := make([]string, 0, len(owners))
	for id := range owners {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	list := store.MembersListID(tx.Tenant())
	var out []Service
	for _, id := range ids {
		f, err := tx.GrpFolder(store.FolderID(id))
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if ok, err := ck.Has(privs.FolderObject(f.ID), privs.StemView); err != nil {
			return nil, err
		} else if !ok {
			continue
		}
		groups, err := PolicyGroupsBelow(tx, f)
		if err != nil {
			return nil, err
		}
		svc := Service{Folder: f}
		for _, g := range groups {
			if g.Status != store.GroupActive {
				continue
			}
			if ok, err := ck.Has(privs.GroupObject(g.ID), privs.View); err != nil {
				return nil, err
			} else if !ok {
				continue
			}
			if member, err := eng.IsMember(tx, now, g.ID, list, identity); err != nil {
				return nil, err
			} else if member {
				svc.Groups = append(svc.Groups, g)
			}
		}
		if len(svc.Groups) > 0 {
			out = append(out, svc)
		}
	}
	slices.SortFunc(out, func(a, b Service) int {
		switch {
		case a.Folder.Name < b.Folder.Name:
			return -1
		case a.Folder.Name > b.Folder.Name:
			return 1
		}
		return 0
	})
	return out, nil
}
