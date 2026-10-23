package perms

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The point-in-time permission view (design §10.10): what an identity could do
// at an instant, from the history of its roles (grp_pit_effective) and of the
// permission and limit assignments (grp_pit_assigns). The heuristics are the
// ones Decide applies. What the history does not keep is taken as it is now: the
// implication closures of resources and actions, and which role the identity was
// a direct member of (every role it held counts as direct, so only the (role,
// identity) pair outranks a role).

type assignSnap struct {
	AssignID   string   `json:"assign_id"`
	DefID      string   `json:"def_id"`
	NameID     string   `json:"name_id"`
	ActionID   string   `json:"action_id"`
	OwnerType  string   `json:"owner_type"`
	OwnerID    string   `json:"owner_id"`
	Disallowed bool     `json:"disallowed"`
	From       *string  `json:"enabled_from"`
	To         *string  `json:"disabled_at"`
	Values     []string `json:"values"`
	// of a membership-owned assignment: the role and identity the membership named
	MemberGroup    string `json:"member_group"`
	MemberIdentity *int64 `json:"member_identity"`
}

func (a assignSnap) dates() (from, to *time.Time, err error) {
	parse := func(s *string) (*time.Time, error) {
		if s == nil {
			return nil, nil
		}
		t, err := store.ParseRT(*s)
		return &t, err
	}
	if from, err = parse(a.From); err != nil {
		return nil, nil, err
	}
	to, err = parse(a.To)
	return from, to, err
}

// LoadAt reads the permission assignments that held at an instant.
func LoadAt(tx *store.TenantTx, at time.Time) (*Set, error) {
	rows, err := tx.GrpPitPermAssignsAt(at)
	if err != nil {
		return nil, err
	}
	var perms []assignSnap
	limits := map[string][]Limit{}
	for _, r := range rows {
		var snap assignSnap
		if err := json.Unmarshal(r.Snapshot, &snap); err != nil {
			return nil, fmt.Errorf("perms: history of assignment %s: %w", r.AssignID, err)
		}
		d, err := attrs.Def(tx, snap.DefID)
		if err != nil {
			continue // the definition is gone: so is what it meant
		}
		switch d.AttrType {
		case store.AttrTypePerm:
			if snap.OwnerType == store.AttrOwnerGroup || snap.OwnerType == store.AttrOwnerMembership {
				perms = append(perms, snap)
			}
		case store.AttrTypeLimit:
			if snap.OwnerType != store.AttrOwnerAssignment {
				continue
			}
			n, err := attrs.Name(tx, snap.NameID)
			if err != nil {
				continue
			}
			vals := make([]string, len(snap.Values))
			for i, v := range snap.Values {
				vals[i] = keyText(v)
			}
			limits[snap.OwnerID] = append(limits[snap.OwnerID], Limit{Name: attrs.NameFullName(d, n), Values: vals})
		}
	}
	s := newSet(tx)
	for _, p := range perms {
		g, subject, ok, err := pitOwnerRole(tx, p)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		from, to, err := p.dates()
		if err != nil {
			return nil, fmt.Errorf("perms: history of assignment %s: %w", p.AssignID, err)
		}
		a, err := s.assignment(p.AssignID, p.DefID, p.NameID, p.ActionID, p.Disallowed, from, to, g, subject, limits[p.AssignID])
		if err != nil {
			continue // a name or action deleted since: it is not a permission any more
		}
		s.Assignments = append(s.Assignments, a)
	}
	return s, nil
}

// pitOwnerRole is ownerRole for history: a role that has since been deleted still
// counts (its name is kept). A membership-owned assignment names its role and
// identity from the snapshot, so a membership row deleted since still counts
// (a disallow on it applied then); history written before the snapshot kept
// them falls back to the row, and a row that is gone names no identity.
func pitOwnerRole(tx *store.TenantTx, p assignSnap) (*store.NativeGroup, *int64, bool, error) {
	if p.OwnerType == store.AttrOwnerGroup {
		g, err := tx.GrpGroup(store.GroupID(p.OwnerID))
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, false, nil
		}
		return g, nil, err == nil, err
	}
	gid, identity := store.GroupID(p.MemberGroup), p.MemberIdentity
	if gid == "" {
		m, err := tx.GrpDirectMembership(p.OwnerID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, false, nil
		}
		if err != nil {
			return nil, nil, false, err
		}
		gid, identity = m.GroupID, m.MemberIdentity
	}
	if identity == nil {
		return nil, nil, false, nil
	}
	g, err := tx.GrpGroup(gid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, false, nil
	}
	return g, identity, err == nil, err
}

// SubjectAt reads the roles an identity was effectively in at an instant.
func SubjectAt(tx *store.TenantTx, identity int64, at time.Time) (Subject, error) {
	list := store.MembersListID(tx.Tenant())
	sub := Subject{Identity: identity, Roles: map[store.GroupID]bool{}, Direct: map[store.GroupID]bool{}}
	const page = 500
	for off := 0; ; off += page {
		rows, _, err := tx.GrpPitGroupsOfIdentity(identity, list, at, page, off)
		if err != nil {
			return sub, err
		}
		for _, r := range rows {
			sub.Roles[store.GroupID(r.Group)] = true
			sub.Direct[store.GroupID(r.Group)] = true
		}
		if len(rows) < page {
			return sub, nil
		}
	}
}
