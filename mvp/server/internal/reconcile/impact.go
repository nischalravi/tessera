package reconcile

import (
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ImpactGraph answers "what does this group reach?" from the live graph: a
// staged group that already exists live (same system and external id) is
// followed through maps_to and grants edges to permissions (§6.4), for
// example an Okta group federated into an AWS role.
type ImpactGraph struct {
	groupNode map[string]string          // "system|xid" → "group:<id>"
	out       map[string][]string        // node → nodes it maps to or grants
	memo      map[string]map[string]bool // node → permission nodes reached
}

// BuildImpact loads the live group and edge maps.
func BuildImpact(c *store.TenantTx) (*ImpactGraph, error) {
	g := &ImpactGraph{groupNode: map[string]string{}, out: map[string][]string{}, memo: map[string]map[string]bool{}}
	groups, err := c.Groups() // id order
	if err != nil {
		return nil, err
	}
	for _, x := range groups {
		g.groupNode[x.System+"|"+x.ExternalID] = fmt.Sprintf("group:%d", x.ID)
	}
	edges, err := c.Edges()
	if err != nil {
		return nil, err
	}
	for _, e := range edges {
		if e.Relation != "maps_to" && e.Relation != "grants" {
			continue
		}
		g.out[e.Src] = append(g.out[e.Src], e.Dst)
	}
	return g, nil
}

func (g *ImpactGraph) reach(node string, visiting map[string]bool) map[string]bool {
	if r, ok := g.memo[node]; ok {
		return r
	}
	r := map[string]bool{}
	if visiting[node] {
		return r
	}
	visiting[node] = true
	for _, n := range g.out[node] {
		if strings.HasPrefix(n, "perm:") {
			r[n] = true
			continue
		}
		for p := range g.reach(n, visiting) {
			r[p] = true
		}
	}
	delete(visiting, node)
	g.memo[node] = r
	return r
}

// Permissions returns the distinct live permissions the staged groups reach.
func (g *ImpactGraph) Permissions(system string, groupXIDs []string) int {
	if g == nil {
		return 0
	}
	all := map[string]bool{}
	for _, x := range groupXIDs {
		if n, ok := g.groupNode[system+"|"+x]; ok {
			for p := range g.reach(n, map[string]bool{}) {
				all[p] = true
			}
		}
	}
	return len(all)
}
