package seed

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// demoRole is a business role of the demo company (issue #161), naming its
// entitlements by system and external id.
type demoRole struct {
	name, desc, owner, risk string
	requestable             bool
	rule                    *roles.Rule
	ents                    [][2]string
}

var demoRoles = []demoRole{
	{"Backend engineer", "Day-one access for backend engineers: the engineering Okta groups and the backend GitHub team.",
		"Kofi Mensah", "medium", false,
		&roles.Rule{Department: []string{"Engineering"}, Title: []string{"Engineering Manager, Backend", "Senior Software Engineer", "Software Engineer"}},
		[][2]string{{"okta", "engineering"}, {"okta", "eng-backend"}, {"github", "team/backend"}}},
	{"Frontend engineer", "Source control and the engineering Okta groups for the web team.", "Anders Zeller", "low", false,
		&roles.Rule{Department: []string{"Engineering"}, Title: []string{"Engineering Manager, Frontend", "Frontend Engineer"}},
		[][2]string{{"okta", "engineering"}, {"okta", "eng-frontend"}, {"github", "team/frontend"}}},
	{"Platform on-call", "Standing read-only access for the on-call rota; production admin stays JIT only.", "Ingrid Lindqvist", "high", true,
		nil, [][2]string{{"okta", "eng-platform"}, {"github", "team/platform"}, {"aws", "role/ProdReadOnly"}}},
	{"Data analyst", "Warehouse read access and the data team's tools.", "Sana Iyer", "medium", false,
		&roles.Rule{Department: []string{"Data"}}, [][2]string{{"okta", "data-team"}, {"github", "team/data"}, {"snowflake", "role/ANALYST"}}},
	{"Finance operations", "Accounts-payable processing in Workday. Must not be combined with AP Approver (SoD).", "Beatrix Pemberton", "high", true,
		nil, [][2]string{{"okta", "finance"}, {"workday", "sg-ap-clerk"}, {"snowflake", "role/FINANCE_ANALYST"}}},
	{"Support agent", "Customer support tooling.", "Esme Thornbury", "low", false,
		&roles.Rule{Department: []string{"Support"}}, [][2]string{{"okta", "support"}}},
}

// seedRoles saves the demo's business roles for a tenant that has their
// groups. A rule member is added only when they already hold every
// entitlement, so seeding grants nothing: the rest show in the role's
// reconcile plan and drift. It writes no audit event.
func seedRoles(c *store.TenantTx, now time.Time) error {
	people, err := c.Identities()
	if err != nil {
		return err
	}
	byName, byID := map[string]*store.Identity{}, map[int64]*store.Identity{}
	for _, p := range people {
		byName[p.Name], byID[p.ID] = p, p
	}
	for _, d := range demoRoles {
		var ents []int64
		for _, e := range d.ents {
			g, err := c.GroupByXID(e[0], e[1])
			if errors.Is(err, store.ErrNotFound) {
				continue
			} else if err != nil {
				return err
			}
			ents = append(ents, g.ID)
		}
		if len(ents) != len(d.ents) {
			continue // not the demo company
		}
		r := &store.BusinessRole{ID: uuid.NewString(), Name: d.name, Description: d.desc, Risk: d.risk,
			Requestable: d.requestable, Status: store.RoleActive, Version: 1, CreatedAt: now, UpdatedAt: now}
		if o := byName[d.owner]; o != nil {
			r.OwnerIdentityID = &o.ID
		}
		if d.rule != nil {
			b, err := json.Marshal(d.rule)
			if err != nil {
				return err
			}
			s := string(b)
			r.Birthright = &s
		}
		if err := c.InsertBusinessRole(r); err != nil {
			return fmt.Errorf("seed: role %s: %w", d.name, err)
		}
		if err := c.SetRoleEntitlements(r.ID, ents); err != nil {
			return err
		}
		snap, err := roles.Snapshot(r, ents)
		if err != nil {
			return err
		}
		if err := c.AddRoleVersion(&store.RoleVersion{RoleID: r.ID, Version: 1, Snapshot: snap, Actor: "seed", ChangedAt: now}); err != nil {
			return err
		}
		if d.rule == nil {
			continue
		}
		drift, err := roles.RoleDrift(c, r.ID, now)
		if err != nil {
			return err
		}
		for _, h := range drift.Holders {
			if p := byID[h.IdentityID]; p != nil && len(h.Held) == len(ents) && d.rule.Matches(p) {
				if err := c.AddRoleMember(&store.RoleMember{RoleID: r.ID, IdentityID: p.ID, Source: store.MemberRule, AssignedAt: now}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
