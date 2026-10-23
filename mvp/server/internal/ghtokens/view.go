package ghtokens

import (
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// OwnerView is the identity accountable for a credential.
type OwnerView struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// View is the API rendering of a credential. It holds metadata only: GitHub
// never sends a token or secret value, and none is stored.
type View struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Name       string     `json:"name"`
	OwnerLogin string     `json:"owner_login"`
	Owner      *OwnerView `json:"owner"`
	Scopes     []string   `json:"scopes"`
	Visibility string     `json:"visibility,omitempty"`
	CreatedAt  *string    `json:"created_at"`
	RotatedAt  *string    `json:"last_rotated_at"`
	ExpiresAt  *string    `json:"expires_at"`
	LastUsedAt *string    `json:"last_used_at"`
	// AgeDays counts from the last rotation (an Actions secret's update), else from creation or authorization.
	AgeDays  int      `json:"age_days"`
	Flags    []string `json:"flags"`
	Risk     int      `json:"risk"`
	Status   string   `json:"status"`
	LastSeen string   `json:"last_seen"`
}

// Summary counts the active credentials.
type Summary struct {
	Total   int            `json:"total"`
	ByKind  map[string]int `json:"by_kind"`
	Stale   int            `json:"stale"`
	Risky   int            `json:"risky"` // risk of 50 or more
	NoOwner int            `json:"no_owner"`
}

// List renders the tenant's active credentials, highest risk first.
func List(tx *store.TenantTx, now time.Time) ([]View, Summary, error) {
	rows, err := tx.GitHubTokens()
	if err != nil {
		return nil, Summary{}, err
	}
	people, _, err := tx.IdentityMap()
	if err != nil {
		return nil, Summary{}, err
	}
	out := []View{}
	sum := Summary{ByKind: map[string]int{}}
	for _, t := range rows {
		if t.Status != store.GHTokenActive {
			continue
		}
		owner, state := (*OwnerView)(nil), OwnerNone
		if t.OwnerIdentityID != nil {
			if p := people[*t.OwnerIdentityID]; p != nil {
				owner = &OwnerView{ID: p.ID, Name: p.Name, Status: p.Status}
				state = OwnerActive
				if p.Status != "active" {
					state = OwnerInactive
				}
			}
		}
		as := Assess(t, state, now)
		scopes := append([]string{}, t.Scopes...)
		v := View{ID: t.ID, Kind: t.Kind, Name: t.Name, OwnerLogin: t.OwnerLogin, Owner: owner, Scopes: scopes,
			Visibility: t.Visibility, CreatedAt: timeutil.ISOPtr(t.CreatedAt), RotatedAt: timeutil.ISOPtr(t.RotatedAt),
			ExpiresAt: timeutil.ISOPtr(t.ExpiresAt), LastUsedAt: timeutil.ISOPtr(t.LastUsedAt), AgeDays: as.AgeDays,
			Flags: as.Flags, Risk: as.Score, Status: t.Status, LastSeen: timeutil.ISO(t.LastSeen)}
		out = append(out, v)
		sum.Total++
		sum.ByKind[t.Kind]++
		for _, f := range as.Flags {
			switch f {
			case FlagStale:
				sum.Stale++
			case FlagOrphaned:
				sum.NoOwner++
			}
		}
		if as.Score >= 50 {
			sum.Risky++
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].Name < out[j].Name
	})
	return out, sum, nil
}
