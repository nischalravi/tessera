package mining

import (
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Load reads the tenant's standing access: for every active person, the
// groups their active accounts hold through a grant that does not expire
// (a JIT or other timed grant is not a pattern to turn into a role), and the
// entitlement sets of the active business roles. Tessera's own reference groups
// (access.IsRefGroup: assurance level, sponsor eligibility) are derived, not
// grantable access, so they are left out of both (#405). A missing attribute is "".
func Load(tx *store.TenantTx) (Input, error) {
	groups, err := tx.Groups()
	if err != nil {
		return Input{}, err
	}
	internal := map[int64]bool{}
	for _, g := range groups {
		if access.IsRefGroup(g) {
			internal[g.ID] = true
		}
	}
	people, err := tx.Identities()
	if err != nil {
		return Input{}, err
	}
	accounts, err := tx.Accounts()
	if err != nil {
		return Input{}, err
	}
	owner := map[int64]int64{} // account -> identity
	for _, a := range accounts {
		if a.Status == "active" && a.IdentityID != nil {
			owner[a.ID] = *a.IdentityID
		}
	}
	edges, err := tx.Edges()
	if err != nil {
		return Input{}, err
	}
	held := map[int64]map[int64]bool{}
	for _, e := range edges {
		if e.ExpiresAt != nil {
			continue
		}
		sk, aid, err := graph.ParseKey(e.Src)
		if err != nil || sk != "account" {
			continue
		}
		dk, gid, err := graph.ParseKey(e.Dst)
		if err != nil || dk != "group" || internal[gid] {
			continue
		}
		id, ok := owner[aid]
		if !ok {
			continue
		}
		if held[id] == nil {
			held[id] = map[int64]bool{}
		}
		held[id][gid] = true
	}
	var in Input
	str := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	for _, p := range people {
		if p.Status != "active" || len(held[p.ID]) == 0 {
			continue
		}
		x := Person{ID: p.ID, Department: str(p.Department), Title: str(p.Title), Type: p.Type}
		for g := range held[p.ID] {
			x.Entitlements = append(x.Entitlements, g)
		}
		in.People = append(in.People, x)
	}
	roles, err := tx.BusinessRoles()
	if err != nil {
		return Input{}, err
	}
	ents, err := tx.AllRoleEntitlements()
	if err != nil {
		return Input{}, err
	}
	byRole := map[string][]int64{}
	for _, e := range ents {
		if internal[e.GroupID] {
			continue
		}
		byRole[e.RoleID] = append(byRole[e.RoleID], e.GroupID)
	}
	for _, r := range roles {
		if r.Status == store.RoleActive {
			in.Roles = append(in.Roles, Role{ID: r.ID, Entitlements: byRole[r.ID]})
		}
	}
	return in, nil
}
