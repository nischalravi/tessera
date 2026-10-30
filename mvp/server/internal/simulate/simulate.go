// Package simulate is the what-if engine: apply hypothetical graph changes to
// a copy of the graph and diff effective permissions and policy violations.
package simulate

import (
	"fmt"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

// AddEdge is a hypothetical new grant. A non-nil ExpiresAt makes it a
// time-boxed JIT grant, which never counts as standing access.
type AddEdge struct {
	Src, Dst, Relation string
	ExpiresAt          *time.Time
}

// Request lists the hypothetical changes.
type Request struct {
	RemoveEdgeIDs     []int64
	RemoveEdges       [][2]string
	AddEdges          []AddEdge
	DisableAccountIDs []int64
}

// Inputs are the precomputed pieces a caller may already have.
type Inputs struct {
	Now      time.Time
	Policies []*policy.Policy
	// AfterPolicies, when set, are the policies evaluated on the simulated graph, where the change itself
	// alters the policies (a proposed agent scope or SoD rule); nil evaluates Policies on both sides.
	AfterPolicies []*policy.Policy
	Usage         *usage.Index
	Base          *graph.Snapshot
}

// Removed describes a permission an identity would lose.
type Removed struct {
	PermKey     string            `json:"perm_key"`
	Action      string            `json:"action"`
	Resource    string            `json:"resource"`
	System      string            `json:"system"`
	Privileged  bool              `json:"privileged"`
	Tags        []string          `json:"tags"`
	Usage       usage.Description `json:"usage"`
	UsedLast30d bool              `json:"used_last_30d"`
}

// Added describes a permission an identity would gain.
type Added struct {
	PermKey    string   `json:"perm_key"`
	Action     string   `json:"action"`
	Resource   string   `json:"resource"`
	System     string   `json:"system"`
	Privileged bool     `json:"privileged"`
	Tags       []string `json:"tags"`
	Path       string   `json:"path"`
}

// IdentityChange is the per-identity diff.
type IdentityChange struct {
	IdentityID int64     `json:"identity_id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Removed    []Removed `json:"removed"`
	Added      []Added   `json:"added"`
}

// Summary totals the diff.
type Summary struct {
	IdentitiesAffected   int `json:"identities_affected"`
	PermissionsRemoved   int `json:"permissions_removed"`
	PermissionsAdded     int `json:"permissions_added"`
	RemovedRecentlyUsed  int `json:"removed_recently_used"`
	RemovedPrivileged    int `json:"removed_privileged"`
	ViolationsBefore     int `json:"violations_before"`
	ViolationsAfter      int `json:"violations_after"`
	ViolationsResolved   int `json:"violations_resolved"`
	ViolationsIntroduced int `json:"violations_introduced"`
}

// Result is the simulation outcome.
type Result struct {
	Changes    []ojson.Object   `json:"changes"`
	Summary    Summary          `json:"summary"`
	Identities []IdentityChange `json:"identities"`
	Violations policy.Diff      `json:"violations"`
}

// Run simulates req. Missing inputs (usage, base graph) are built from c.
// It returns *graph.UnknownNodeError for edges or accounts not in the graph.
func Run(c *store.TenantTx, req Request, in Inputs) (*Result, error) {
	var err error
	if in.Usage == nil {
		if in.Usage, err = usage.Build(c, in.Now); err != nil {
			return nil, err
		}
	}
	base := in.Base
	if base == nil {
		if base, err = graph.Build(c, in.Now); err != nil {
			return nil, err
		}
	}
	after := base.Copy()
	applied := []ojson.Object{}
	for _, eid := range req.RemoveEdgeIDs {
		src, dst, ok := after.RemoveEdgeID(eid)
		ch := ojson.Object{{Key: "op", Value: "remove"}, {Key: "edge_id", Value: eid}}
		if ok {
			ch = append(ch, ojson.KV{Key: "edge", Value: []string{src, dst}},
				ojson.KV{Key: "label", Value: base.Label(src) + " → " + base.Label(dst)})
		} else {
			ch = append(ch, ojson.KV{Key: "edge", Value: nil}, ojson.KV{Key: "label", Value: "not found"})
		}
		applied = append(applied, ch)
	}
	for _, e := range req.RemoveEdges {
		ok := after.RemoveEdge(e[0], e[1])
		label := ""
		if base.HasNode(e[0]) && base.HasNode(e[1]) {
			label = base.Label(e[0]) + " → " + base.Label(e[1])
		}
		applied = append(applied, ojson.Object{{Key: "op", Value: "remove"}, {Key: "edge", Value: []string{e[0], e[1]}},
			{Key: "found", Value: ok}, {Key: "label", Value: label}})
	}
	for _, e := range req.AddEdges {
		rel := e.Relation
		if rel == "" {
			rel = "member_of"
		}
		source := "simulated"
		if e.ExpiresAt != nil {
			source = "jit" // time-boxed: the graph and policies treat it as non-standing
		}
		if err := after.AddEdge(e.Src, e.Dst, rel, source, e.ExpiresAt); err != nil {
			return nil, err
		}
		applied = append(applied, ojson.Object{{Key: "op", Value: "add"}, {Key: "edge", Value: []string{e.Src, e.Dst}},
			{Key: "label", Value: base.Label(e.Src) + " → " + base.Label(e.Dst)}})
	}
	for _, aid := range req.DisableAccountIDs {
		if err := after.SetAccountStatus(aid, "disabled"); err != nil {
			return nil, err
		}
		applied = append(applied, ojson.Object{{Key: "op", Value: "disable_account"}, {Key: "account_id", Value: aid},
			{Key: "label", Value: base.Label(graph.Key("account", aid))}})
	}

	effBefore, effAfter := base.AllEffective(), after.AllEffective()
	changes := graph.DiffEffective(effBefore, effAfter)
	iids := make([]int64, 0, len(changes))
	for iid := range changes {
		iids = append(iids, iid)
	}
	sort.Slice(iids, func(i, j int) bool { return iids[i] < iids[j] })

	res := &Result{Changes: applied, Identities: []IdentityChange{}}
	for _, iid := range iids {
		ch := changes[iid]
		node := base.Node(graph.Key("identity", iid))
		ic := IdentityChange{IdentityID: iid, Name: node.Label, Type: node.Type, Removed: []Removed{}, Added: []Added{}}
		for _, pk := range ch.Removed {
			ep := effBefore[iid].M[pk]
			u := in.Usage.Describe(iid, ep.PermID)
			recently := u.DaysSinceUsed != nil && *u.DaysSinceUsed < 30
			ic.Removed = append(ic.Removed, Removed{pk, ep.Action, ep.ResourceName, ep.System, ep.Privileged, ep.Tags, u, recently})
			if recently {
				res.Summary.RemovedRecentlyUsed++
			}
			if ep.Privileged {
				res.Summary.RemovedPrivileged++
			}
		}
		for _, pk := range ch.Added {
			ep := effAfter[iid].M[pk]
			path := ""
			if len(ep.Paths) > 0 {
				path = after.PathText(ep.Paths[0])
			}
			ic.Added = append(ic.Added, Added{pk, ep.Action, ep.ResourceName, ep.System, ep.Privileged, ep.Tags, path})
		}
		res.Summary.IdentitiesAffected++
		res.Summary.PermissionsRemoved += len(ic.Removed)
		res.Summary.PermissionsAdded += len(ic.Added)
		res.Identities = append(res.Identities, ic)
	}

	vBefore, err := policy.Evaluate(in.Policies, policy.NewContext(base, c, in.Now))
	if err != nil {
		return nil, fmt.Errorf("simulate: evaluate before: %w", err)
	}
	afterPolicies := in.Policies
	if in.AfterPolicies != nil {
		afterPolicies = in.AfterPolicies
	}
	vAfter, err := policy.Evaluate(afterPolicies, policy.NewContext(after, c, in.Now))
	if err != nil {
		return nil, fmt.Errorf("simulate: evaluate after: %w", err)
	}
	res.Violations = policy.DiffViolations(vBefore, vAfter)
	res.Summary.ViolationsBefore = len(vBefore)
	res.Summary.ViolationsAfter = len(vAfter)
	res.Summary.ViolationsResolved = len(res.Violations.Resolved)
	res.Summary.ViolationsIntroduced = len(res.Violations.Introduced)
	return res, nil
}
