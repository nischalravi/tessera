package loaders

import (
	"slices"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Impact is the downstream impact of a held run (K7): what the plan would
// change beyond the loader's own groups, so the person who decides sees who
// would lose what, and whether the people who would lose it use it.
type Impact struct {
	// AddedIdentities and RemovedIdentities count distinct people.
	AddedIdentities   int `json:"added_identities"`
	RemovedIdentities int `json:"removed_identities"`
	// Groups are the groups with the most removals first (at most 50).
	Groups []GroupImpact `json:"groups"`
	// ParentGroups are the groups that contain a changed group, through nesting
	// or as a factor of a composite or policy group: their members may change
	// too. PolicyGroups are those that are composite or policy groups.
	ParentGroups []ParentImpact `json:"parent_groups"`
	PolicyGroups []ParentImpact `json:"policy_groups"`
	// ProvisionedTargets are the provisioning targets that change: none until
	// the provisioning framework (GR-11) lands.
	ProvisionedTargets []string `json:"provisioned_targets"`
	// RemovedUsedLast30Days is how many of the people who would be removed used
	// some access in the last 30 days (Tessera's usage records are per
	// permission, not per native group, so this is an upper bound for what the
	// groups grant).
	RemovedUsedLast30Days int    `json:"removed_used_last_30_days"`
	Note                  string `json:"note"`
}

// GroupImpact is one changed group.
type GroupImpact struct {
	Name    string `json:"name"`
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
	Current int    `json:"current"`
	Size    int    `json:"size"`
	Missing bool   `json:"missing,omitempty"`
	Action  string `json:"action,omitempty"`
}

// ParentImpact names a group a changed group feeds.
type ParentImpact struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Because    string `json:"because"`
}

const (
	maxImpactGroups = 50
	usageWindow     = 30 * 24 * time.Hour
)

// ComputeImpact describes what a plan would do downstream.
func ComputeImpact(tx *store.TenantTx, p *Plan, now time.Time) (*Impact, error) {
	imp := &Impact{Groups: []GroupImpact{}, ParentGroups: []ParentImpact{}, PolicyGroups: []ParentImpact{},
		ProvisionedTargets: []string{},
		Note: "Provisioned targets arrive with the provisioning framework. Usage is Tessera's per-permission usage record: " +
			"it is not narrowed to what these groups grant."}
	added, removed := map[int64]bool{}, map[int64]bool{}
	parents := map[string]ParentImpact{}
	for i := range p.Groups {
		g := &p.Groups[i]
		if len(g.Add) == 0 && len(g.Remove) == 0 && !g.Missing {
			continue
		}
		for _, id := range g.Add {
			added[id] = true
		}
		for _, id := range g.Remove {
			removed[id] = true
		}
		imp.Groups = append(imp.Groups, GroupImpact{Name: g.Name, Added: len(g.Add), Removed: len(g.Remove), Current: g.Current,
			Size: g.Size, Missing: g.Missing, Action: g.Action})
		if g.GroupID == "" || (len(g.Remove) == 0 && !g.Missing) {
			continue // only a loss can break what depends on the group
		}
		anc, err := tx.GrpClosureAncestors(store.GroupID(g.GroupID))
		if err != nil {
			return nil, err
		}
		for _, a := range anc {
			if a.Ancestor == store.GroupID(g.GroupID) {
				continue
			}
			parent, err := tx.GrpGroup(a.Ancestor)
			if err != nil {
				return nil, err
			}
			if parent.Status == store.GroupDeleted {
				continue
			}
			if _, seen := parents[string(parent.ID)]; !seen {
				parents[string(parent.ID)] = ParentImpact{ID: string(parent.ID), Name: parent.Name,
					Definition: string(parent.Definition), Because: g.Name}
			}
		}
	}
	imp.AddedIdentities, imp.RemovedIdentities = len(added), len(removed)
	sort.SliceStable(imp.Groups, func(i, j int) bool {
		if imp.Groups[i].Removed != imp.Groups[j].Removed {
			return imp.Groups[i].Removed > imp.Groups[j].Removed
		}
		return imp.Groups[i].Name < imp.Groups[j].Name
	})
	if len(imp.Groups) > maxImpactGroups {
		imp.Groups = imp.Groups[:maxImpactGroups]
	}
	ids := make([]string, 0, len(parents))
	for id := range parents {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		pi := parents[id]
		imp.ParentGroups = append(imp.ParentGroups, pi)
		if pi.Definition != string(store.DefinitionBasic) {
			imp.PolicyGroups = append(imp.PolicyGroups, pi)
		}
	}
	if len(removed) > 0 {
		agg, err := tx.UsageAggregates(now.Add(-usageWindow))
		if err != nil {
			return nil, err
		}
		used := map[int64]bool{}
		for _, a := range agg {
			if a.LastUsed != nil && !a.LastUsed.Before(now.Add(-usageWindow)) {
				used[a.IdentityID] = true
			}
		}
		for id := range removed {
			if used[id] {
				imp.RemovedUsedLast30Days++
			}
		}
	}
	return imp, nil
}
