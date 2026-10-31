// Package blast is the unified blast-radius preview of a policy change (issue #654, AC-8; design
// docs/design/access-as-code-repo.md section 8). It compiles one change into the two things the platform can
// replay without touching anything:
//
//   - the graph edits and policy changes of a policy bundle (roles, agent scopes, SoD rules, JIT eligibility), which
//     internal/simulate runs against the tenant's graph, and
//   - AWS operations (Operation, a snapshot.PolicyChange with a provenance label), which snapshot.Apply turns into a
//     head snapshot that internal/aws/query diffs against the base.
//
// Summarize joins the two answers (AWS principals reach identities through the aws accounts the collector
// materialized) and reports who gains and loses access by identity type and by resource, with the policy
// violations before and after. Everything here is pure: it reads through a tenant transaction and writes nothing,
// and its output is sorted, so the same change always gives the same bytes (diff_sha256), ready to post on a pull
// request. Terraform plans (AC-9) feed it by producing Operations.
package blast

import (
	"fmt"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agentscope"
	"github.com/nischalravi/tessera/mvp/server/internal/agentscopeascode"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jitascode"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/sodascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Operation is one hypothetical change to the AWS estate: a snapshot.PolicyChange and where it came from. Source is
// free text for the reader of the answer (for example "terraform:aws_iam_policy.deploy"); the Terraform plan reader
// of AC-9 fills it, and nothing else depends on it.
type Operation struct {
	snapshot.PolicyChange
	Source string `json:"source,omitempty"`
}

// Changes returns the operations as the changes snapshot.Apply takes, in order.
func Changes(ops []Operation) []snapshot.PolicyChange {
	out := make([]snapshot.PolicyChange, len(ops))
	for i, o := range ops {
		out[i] = o.PolicyChange
	}
	return out
}

// Options say whose bundle it is and how large a change may be.
type Options struct {
	Tenant string // the session's tenant slug; tessera.yaml must name it
	// MaxSteps bounds the writes of the bundle and the AWS operations together (TESSERA_POLICY_MAX_STEPS); 0 is
	// rolesascode.DefaultMaxSteps.
	MaxSteps int
	Now      time.Time
	// Risks are the SoD risks checked now (sod.Load); the bundle's SoD rules are applied to them.
	Risks []*sod.Risk
}

func (o Options) limit() int {
	if o.MaxSteps > 0 {
		return o.MaxSteps
	}
	return rolesascode.DefaultMaxSteps
}

// Limit is the most steps a change may make (MaxSteps, or the default).
func (o Options) Limit() int { return o.limit() }

// KindSummary is what the bundle does to one kind of object, as that kind's plan counts it.
type KindSummary struct {
	Kind      string `json:"kind"` // agents, jit, roles or sod
	Mode      string `json:"mode,omitempty"`
	Created   int    `json:"created"`
	Updated   int    `json:"updated"`
	Retired   int    `json:"retired"`
	Unchanged int    `json:"unchanged"`
	// Steps are the writes the apply would make; GrantsAdded and GrantsRemoved are the graph edits roles make.
	Steps         int    `json:"steps"`
	GrantsAdded   int    `json:"grants_added,omitempty"`
	GrantsRemoved int    `json:"grants_removed,omitempty"`
	PlanSHA256    string `json:"plan_sha256"`
}

// Compiled is a bundle turned into what the simulator replays.
type Compiled struct {
	BundleSHA256 string
	// Request holds the graph edits (the role grants the plan adds and removes).
	Request simulate.Request
	// Risks and Scopes are the SoD risks and agent scopes in force after the bundle; they matter only when
	// RisksChanged or ScopesChanged says the bundle touches that kind.
	Risks         []*sod.Risk
	RisksChanged  bool
	Scopes        []*agentscope.Doc
	ScopesChanged bool
	Kinds         []KindSummary
	// Steps is the total of the kinds' writes, what the ceiling bounds.
	Steps int
}

// Empty reports that the bundle changes nothing the simulator can show: no edit, no rule, no scope.
func (c *Compiled) Empty() bool {
	r := &c.Request
	return len(r.AddEdges) == 0 && len(r.RemoveEdgeIDs) == 0 && !c.RisksChanged && !c.ScopesChanged
}

// Compile plans each kind of object the bundle holds (or manages) against the tenant, exactly as that kind's plan
// route does, and gathers what the plans would change in the graph and in the policies. It writes nothing: run it in
// a read transaction. A bundle that is not valid is a *rolesascode.InvalidError; a plan over the ceiling is a
// *roles.Error with status 413.
func Compile(tx *store.TenantTx, files policybundle.Files, opt Options) (*Compiled, error) {
	out := &Compiled{BundleSHA256: rolesascode.Digest(files), Kinds: []KindSummary{}}
	if len(files) == 0 {
		return out, nil
	}
	b, diags := policybundle.Load(files, nil)
	if len(diags) > 0 {
		ds := make([]rolesascode.Diag, len(diags))
		for i, d := range diags {
			ds[i] = rolesascode.Diag{Path: d.Path, Line: d.Line, Code: d.Code, Msg: d.Msg}
		}
		return nil, &rolesascode.InvalidError{Diags: ds}
	}
	if b.Config.Tenant != opt.Tenant {
		return nil, &rolesascode.InvalidError{Diags: []rolesascode.Diag{{Path: policybundle.ConfigFile, Code: "tenant_mismatch",
			Msg: fmt.Sprintf("tessera.yaml names tenant %q; this is %q", b.Config.Tenant, opt.Tenant)}}}
	}
	has := func(kind string, n int) bool { return b.Config.Manage[kind] != "" || n > 0 }
	ropt := rolesascode.Options{Tenant: opt.Tenant, MaxSteps: opt.MaxSteps}

	if has("roles", len(b.Roles)) {
		plan, err := rolesascode.Build(tx, files, ropt, opt.Now)
		if err != nil {
			return nil, err
		}
		addRoleEdits(&out.Request, plan.AllSteps())
		out.add(KindSummary{Kind: "roles", Mode: b.Config.Manage["roles"], Created: plan.Created, Updated: plan.Updated,
			Unchanged: plan.Unchanged, Steps: plan.Steps, GrantsAdded: plan.Adds, GrantsRemoved: plan.Removes, PlanSHA256: plan.PlanSHA256})
	}
	if has("agents", len(b.AgentScopes)) {
		plan, err := agentscopeascode.Build(tx, files, ropt)
		if err != nil {
			return nil, err
		}
		if out.Scopes, err = agentscopeascode.Proposed(tx, files, ropt); err != nil {
			return nil, err
		}
		out.ScopesChanged = plan.Created+plan.Updated+plan.Retired > 0
		out.add(KindSummary{Kind: "agents", Mode: plan.Mode, Created: plan.Created, Updated: plan.Updated, Retired: plan.Retired,
			Unchanged: plan.Unchanged, Steps: plan.Steps, PlanSHA256: plan.PlanSHA256})
	}
	if has("sod", len(b.Sod)) {
		plan, err := sodascode.Build(tx, files, ropt)
		if err != nil {
			return nil, err
		}
		if out.Risks, err = sodascode.Proposed(tx, files, ropt, opt.Risks); err != nil {
			return nil, err
		}
		out.RisksChanged = plan.Created+plan.Updated+plan.Retired > 0
		out.add(KindSummary{Kind: "sod", Mode: plan.Mode, Created: plan.Created, Updated: plan.Updated, Retired: plan.Retired,
			Unchanged: plan.Unchanged, Steps: plan.Steps, PlanSHA256: plan.PlanSHA256})
	}
	if has("jit", len(b.Jit)) {
		// Eligibility decides who may ask for time-boxed access; it adds no standing grant, so it moves nothing in the
		// graph. It is counted so the answer names every kind the bundle touches.
		plan, err := jitascode.Build(tx, files, ropt)
		if err != nil {
			return nil, err
		}
		out.add(KindSummary{Kind: "jit", Mode: plan.Mode, Created: plan.Created, Updated: plan.Updated, Retired: plan.Retired,
			Unchanged: plan.Unchanged, Steps: plan.Steps, PlanSHA256: plan.PlanSHA256})
	}
	sort.Slice(out.Kinds, func(i, j int) bool { return out.Kinds[i].Kind < out.Kinds[j].Kind })
	return out, nil
}

func (c *Compiled) add(k KindSummary) {
	c.Kinds = append(c.Kinds, k)
	c.Steps += k.Steps
}

// CheckCeiling refuses a change whose bundle writes and AWS operations together pass the limit (413 plan_too_large):
// the preview replays all of them in memory, so an unbounded one would be a way to make the server do unbounded work.
func CheckCeiling(opt Options, bundleSteps, operations int) error {
	if n, limit := bundleSteps+operations, opt.limit(); n > limit {
		return &roles.Error{Status: 413, Code: "plan_too_large",
			Msg: fmt.Sprintf("the change makes %d steps (bundle writes and AWS operations); a preview takes at most %d. Split it into smaller changes", n, limit)}
	}
	return nil
}

// addRoleEdits turns the grant steps of a roles plan into graph edits: a granted group is an edge from the person's
// account to the group, a removed grant is the edge id. A grant two roles both want is added once.
func addRoleEdits(req *simulate.Request, steps []roles.Step) {
	type pair struct{ src, dst string }
	added, removed := map[pair]bool{}, map[int64]bool{}
	for _, s := range steps {
		switch s.Action {
		case roles.AddGrant:
			if s.AccountID == nil {
				continue
			}
			p := pair{graph.Key("account", *s.AccountID), graph.Key("group", s.GroupID)}
			if !added[p] {
				added[p] = true
				req.AddEdges = append(req.AddEdges, simulate.AddEdge{Src: p.src, Dst: p.dst, Relation: "member_of"})
			}
		case roles.RemoveGrant:
			if s.EdgeID != nil && !removed[*s.EdgeID] {
				removed[*s.EdgeID] = true
				req.RemoveEdgeIDs = append(req.RemoveEdgeIDs, *s.EdgeID)
			}
		}
	}
}
