// Package nhi reports non-human identity and AI agent posture.
package nhi

import (
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

const (
	// StaleSecretDays is the age after which a secret counts as stale.
	StaleSecretDays = 90
	// DormantDays is the inactivity after which an NHI counts as dormant.
	DormantDays = 30
)

// SecretView is the API rendering of a secret. It never contains secret material.
type SecretView struct {
	ID            int64   `json:"id"`
	Name          string  `json:"name"`
	Kind          string  `json:"kind"`
	System        string  `json:"system"`
	Account       string  `json:"account"`
	CreatedAt     string  `json:"created_at"`
	AgeDays       int     `json:"age_days"`
	Status        string  `json:"status"`
	LastRotatedAt *string `json:"last_rotated_at"`
	LastUsedAt    *string `json:"last_used_at"`
	LastUsedDays  *int    `json:"last_used_days"`
	Stale         bool    `json:"stale"`
}

// ViewSecret renders a secret and its account.
func ViewSecret(sec *store.Secret, acct *store.Account, now time.Time) SecretView {
	ref := sec.CreatedAt
	if sec.LastRotatedAt != nil {
		ref = *sec.LastRotatedAt
	}
	age := timeutil.Days(now, ref)
	var lastDays *int
	if sec.LastUsedAt != nil {
		d := timeutil.Days(now, *sec.LastUsedAt)
		lastDays = &d
	}
	return SecretView{sec.ID, sec.Name, sec.Kind, sec.System, acct.Username, timeutil.ISO(sec.CreatedAt), age, sec.Status,
		timeutil.ISOPtr(sec.LastRotatedAt), timeutil.ISOPtr(sec.LastUsedAt), lastDays, age > StaleSecretDays}
}

// Owner is an NHI's owner.
type Owner struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Status     string  `json:"status"`
	Department *string `json:"department"`
}

// AccountView is a brief account rendering.
type AccountView struct {
	ID       int64  `json:"id"`
	System   string `json:"system"`
	Username string `json:"username"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
}

// Principal is the identity an agent acts for.
type Principal struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// ChainLink is one hop of owner -> agent -> on_behalf_of.
type ChainLink struct {
	Role   string `json:"role"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// DelegationView describes one delegation of an AI agent.
type DelegationView struct {
	Principal        *Principal  `json:"principal"`
	Scopes           []string    `json:"scopes"`
	Chain            []ChainLink `json:"chain"`
	ExceedsPrincipal []string    `json:"exceeds_principal"`
	ExpiresAt        *string     `json:"expires_at"`
}

// Item is one NHI or agent in the inventory.
type Item struct {
	ID                    int64             `json:"id"`
	Name                  string            `json:"name"`
	Type                  string            `json:"type"`
	Kind                  *string           `json:"kind"`
	Description           *string           `json:"description"`
	Status                string            `json:"status"`
	Owner                 *Owner            `json:"owner"`
	Systems               []string          `json:"systems"`
	Accounts              []AccountView     `json:"accounts"`
	Secrets               []SecretView      `json:"secrets"`
	OldestSecretDays      *int              `json:"oldest_secret_days"`
	EffectivePermissions  int               `json:"effective_permissions"`
	PrivilegedPermissions int               `json:"privileged_permissions"`
	LastActivity          *string           `json:"last_activity"`
	DaysSinceActivity     *int              `json:"days_since_activity"`
	Flags                 []string          `json:"flags"`
	Risk                  int               `json:"risk"`
	Delegations           *[]DelegationView `json:"delegations,omitempty"`
}

var riskWeights = map[string]int{"orphaned": 30, "owner_left": 30, "stale_secret": 15, "dormant": 10, "privileged": 20, "pii_access": 20}

func risk(flags []string) int {
	s := 0
	for _, f := range flags {
		s += riskWeights[f]
	}
	return min(100, s)
}

// Inventory lists every non-human identity with risk flags, highest risk first.
func Inventory(c *store.Conn, g *graph.Snapshot, u *usage.Index) ([]Item, error) {
	now := u.Now
	people, all, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	secrets := map[int64][]SecretView{}
	rows, err := c.SecretsWithAccounts("")
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Account.IdentityID != nil {
			secrets[*r.Account.IdentityID] = append(secrets[*r.Account.IdentityID], ViewSecret(r.Secret, r.Account, now))
		}
	}
	dels, err := c.Delegations("")
	if err != nil {
		return nil, err
	}
	byAgent := map[int64][]*store.Delegation{}
	for _, d := range dels {
		byAgent[d.AgentID] = append(byAgent[d.AgentID], d)
	}
	accounts, err := c.Accounts("WHERE identity_id IS NOT NULL")
	if err != nil {
		return nil, err
	}
	acctsBy := map[int64][]*store.Account{}
	for _, a := range accounts {
		acctsBy[*a.IdentityID] = append(acctsBy[*a.IdentityID], a)
	}

	out := []Item{}
	for _, i := range all {
		if i.Type == "human" {
			continue
		}
		eff := g.EffectivePermissions(i.ID)
		var owner *store.Identity
		if i.OwnerID != nil {
			owner = people[*i.OwnerID]
		}
		secs := secrets[i.ID]
		if secs == nil {
			secs = []SecretView{}
		}
		var last *time.Time
		if t, ok := u.ByIdentity[i.ID]; ok {
			last = &t
		}
		flags := []string{}
		if owner == nil {
			flags = append(flags, "orphaned")
		} else if owner.Status != "active" {
			flags = append(flags, "owner_left")
		}
		for _, s := range secs {
			if s.Stale {
				flags = append(flags, "stale_secret")
				break
			}
		}
		if last == nil || timeutil.Days(now, *last) >= DormantDays {
			flags = append(flags, "dormant")
		}
		priv, pii := 0, false
		for _, ep := range eff.Values() {
			if ep.Privileged {
				priv++
			}
			for _, t := range ep.Tags {
				if t == "pii" {
					pii = true
				}
			}
		}
		if priv > 0 {
			flags = append(flags, "privileged")
		}
		if pii {
			flags = append(flags, "pii_access")
		}
		acctViews := []AccountView{}
		sysSet := map[string]bool{}
		for _, a := range acctsBy[i.ID] {
			acctViews = append(acctViews, AccountView{a.ID, a.System, a.Username, a.Kind, a.Status})
			sysSet[a.System] = true
		}
		systems := make([]string, 0, len(sysSet))
		for s := range sysSet {
			systems = append(systems, s)
		}
		sort.Strings(systems)
		var oldest *int
		for _, s := range secs {
			if oldest == nil || s.AgeDays > *oldest {
				v := s.AgeDays
				oldest = &v
			}
		}
		item := Item{ID: i.ID, Name: i.Name, Type: i.Type, Kind: i.Title, Description: i.Description, Status: i.Status,
			Systems: systems, Accounts: acctViews, Secrets: secs, OldestSecretDays: oldest,
			EffectivePermissions: eff.Len(), PrivilegedPermissions: priv, LastActivity: timeutil.ISOPtr(last),
			DaysSinceActivity: daysSince(now, last), Flags: flags, Risk: risk(flags)}
		if owner != nil {
			item.Owner = &Owner{owner.ID, owner.Name, owner.Status, owner.Department}
		}
		if i.Type == "ai_agent" {
			views := []DelegationView{}
			for _, d := range byAgent[i.ID] {
				views = append(views, delegationView(d, i, people, g))
			}
			item.Delegations = &views
		}
		out = append(out, item)
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Risk != out[b].Risk {
			return out[a].Risk > out[b].Risk
		}
		return out[a].Name < out[b].Name
	})
	return out, nil
}

func daysSince(now time.Time, t *time.Time) *int {
	if t == nil {
		return nil
	}
	d := timeutil.Days(now, *t)
	return &d
}

func delegationView(d *store.Delegation, agent *store.Identity, people map[int64]*store.Identity, g *graph.Snapshot) DelegationView {
	principal := people[d.PrincipalID]
	agentEff := g.EffectivePermissions(agent.ID)
	exceeds := []string{}
	for _, ep := range agentEff.Values() {
		if principal == nil || !g.EffectivePermissions(principal.ID).Has(ep.PermKey) {
			exceeds = append(exceeds, ep.Action+" on "+ep.ResourceName)
		}
	}
	chain := []ChainLink{}
	if agent.OwnerID != nil {
		if owner := people[*agent.OwnerID]; owner != nil {
			chain = append(chain, ChainLink{"owner", owner.Name, owner.Status})
		}
	}
	chain = append(chain, ChainLink{"agent", agent.Name, agent.Status})
	v := DelegationView{Scopes: d.Scopes, Chain: chain, ExceedsPrincipal: exceeds, ExpiresAt: timeutil.ISOPtr(d.ExpiresAt)}
	if principal != nil {
		chain = append(chain, ChainLink{"on_behalf_of", principal.Name, principal.Status})
		v.Chain = chain
		v.Principal = &Principal{principal.ID, principal.Name, principal.Status}
	}
	return v
}
