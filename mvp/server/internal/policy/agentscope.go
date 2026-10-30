package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/agentscope"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Agent scopes as invariants (issue #653, AC-7; design access-as-code-repo.md section 3.5). The tenant's active
// scopes (agents/<key>.yaml, internal/agentscope) are compiled into two graph invariants that WithAgentScopes adds
// to the policies of a tenant that has at least one:
//
//	agent-out-of-scope    default deny: an agent with a scope holds an effective permission whose action class
//	                      (read, write, admin, delegate) or resource (system, environment, tag, sensitivity) no
//	                      scope of the agent allows. Key <scope key>:<identity id>.
//	agent-exceeds-owner   delegation: an agent holds an effective permission its owner does not hold (or, when the
//	                      owner is itself an agent with a scope, one that scope does not allow); an agent may not
//	                      have more than the person who answers for it. Key <scope key>:<identity id>:owner.
//
// The scopes of an agent are those that name it (agent profile source and external id) and those of its blueprint
// (agent link blueprint app id); an agent is in scope when any of them allows the permission. An agent with no
// scope is not checked here: nhi-ownership and the agent views report it. Both findings come from the effective
// permissions of the graph, so what-if simulation, reviews and /api/violations see them like any policy; a finding
// whose every permission is approximate, conditional or unsupported is low fidelity (reported, never blocking).

// The types and ids of the two invariants.
const (
	TypeAgentOutOfScope   = "agent_out_of_scope"
	TypeAgentExceedsOwner = "agent_exceeds_owner"

	PolicyAgentOutOfScope   = "agent-out-of-scope"
	PolicyAgentExceedsOwner = "agent-exceeds-owner"
)

func init() {
	Evaluators[TypeAgentOutOfScope] = evalAgentOutOfScope
	Evaluators[TypeAgentExceedsOwner] = evalAgentExceedsOwner
}

// WithAgentScopes appends the two agent scope invariants to base when the tenant has an active scope. A stored
// scope that no longer reads is an error, never a scope silently dropped: that would turn a ceiling into no check.
func WithAgentScopes(tx *store.TenantTx, base []*Policy) ([]*Policy, error) {
	rows, err := tx.AgentScopes()
	if err != nil {
		return nil, err
	}
	var docs []*agentscope.Doc
	for _, r := range rows {
		if r.Status != store.AgentScopeActive {
			continue
		}
		d, err := agentscope.FromJSON(r.Doc)
		if err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	if len(docs) == 0 {
		return base, nil
	}
	mk := func(id, name, typ, desc string) *Policy {
		return &Policy{ID: id, Name: name, Type: typ, Severity: "high", Description: desc, Spec: map[string]any{},
			Source: "agent scopes (agents/*.yaml)", Enabled: true, AgentScopes: docs}
	}
	return append(append([]*Policy(nil), base...),
		mk(PolicyAgentOutOfScope, "Agent holds access outside its declared scope", TypeAgentOutOfScope,
			"An AI agent with a declared scope holds an effective permission whose action class or resource the scope does not allow."),
		mk(PolicyAgentExceedsOwner, "Agent holds access its owner does not", TypeAgentExceedsOwner,
			"An AI agent with a declared scope holds an effective permission that its owner does not hold."),
	), nil
}

// scoped maps an identity id to the scopes that apply to it, agent scopes before blueprint scopes, then by key.
func scoped(c *Context, docs []*agentscope.Doc) (map[int64][]*agentscope.Doc, error) {
	out := map[int64][]*agentscope.Doc{}
	if c.Conn == nil {
		return out, nil // the selectors need the database
	}
	profiles, err := c.Conn.AgentProfiles()
	if err != nil {
		return nil, err
	}
	links, err := c.Conn.AgentLinks()
	if err != nil {
		return nil, err
	}
	type key struct{ source, ext string }
	identity := map[key]int64{}
	for _, p := range profiles {
		identity[key{p.Source, p.ExternalID}] = p.IdentityID
	}
	byBlueprint := map[string][]int64{}
	for _, l := range links {
		if id, ok := identity[key{l.Source, l.ExternalID}]; ok && l.BlueprintAppID != "" {
			byBlueprint[l.BlueprintAppID] = append(byBlueprint[l.BlueprintAppID], id)
		}
	}
	for _, d := range docs {
		if d.ByBlueprint() {
			for _, id := range byBlueprint[d.Agent.Blueprint] {
				out[id] = append(out[id], d)
			}
		} else if id, ok := identity[key{d.Agent.Source, d.Agent.ExternalID}]; ok {
			out[id] = append(out[id], d)
		}
	}
	for _, l := range out {
		sort.SliceStable(l, func(i, j int) bool {
			if l[i].ByBlueprint() != l[j].ByBlueprint() {
				return !l[i].ByBlueprint()
			}
			return l[i].Key < l[j].Key
		})
	}
	return out, nil
}

func permitted(scopes []*agentscope.Doc, ep *graph.EffectivePermission) bool {
	class := agentscope.ClassOf(ep.Action, ep.Privileged)
	for _, d := range scopes {
		if d.Permits(class, ep.System, ep.Environment, ep.Tags) {
			return true
		}
	}
	return false
}

// agentFinding words a finding about the permissions eps of agent n, with evidence and edges of the first few.
func agentFinding(p *Policy, c *Context, n *graph.Node, key, msg string, scopes []*agentscope.Doc, eps []*graph.EffectivePermission) Violation {
	const shown = 5
	var evidence []string
	var edges [][]string
	weak := true
	seen := map[[2]string]bool{}
	for i, ep := range eps {
		weak = weak && ep.Weak()
		if i >= shown {
			continue
		}
		texts, es := c.evidence(ep, false)
		line := fmt.Sprintf("%s on %s (%s)", ep.Action, ep.ResourceName, agentscope.ClassOf(ep.Action, ep.Privileged))
		if len(texts) > 0 {
			line += ": " + texts[0]
		}
		evidence = append(evidence, line)
		for _, e := range es {
			if k := [2]string{e[0], e[1]}; !seen[k] {
				seen[k] = true
				edges = append(edges, e)
			}
		}
	}
	if len(eps) > shown {
		evidence = append(evidence, fmt.Sprintf("and %d more", len(eps)-shown))
	}
	v := newViolation(p, n.ID, n.Label, key, msg, evidence, edges)
	v.Severity = scopes[0].Severity
	v.LowFidelity = weak
	return v
}

func scopeKeys(scopes []*agentscope.Doc) string {
	ks := make([]string, len(scopes))
	for i, d := range scopes {
		ks[i] = d.Key
	}
	return strings.Join(ks, ", ")
}

func evalAgentOutOfScope(p *Policy, c *Context) ([]Violation, error) {
	by, err := scoped(c, p.AgentScopes)
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, n := range c.idents {
		scopes := by[n.ID]
		if len(scopes) == 0 {
			continue
		}
		var bad []*graph.EffectivePermission
		for _, ep := range c.eff(n.ID).Values() {
			if !permitted(scopes, ep) {
				bad = append(bad, ep)
			}
		}
		if len(bad) == 0 {
			continue
		}
		msg := fmt.Sprintf("%s holds %d permission(s) outside its scope %s", n.Label, len(bad), scopeKeys(scopes))
		out = append(out, agentFinding(p, c, n, fmt.Sprintf("%s:%d", scopes[0].Key, n.ID), msg, scopes, bad))
	}
	return out, nil
}

func evalAgentExceedsOwner(p *Policy, c *Context) ([]Violation, error) {
	by, err := scoped(c, p.AgentScopes)
	if err != nil {
		return nil, err
	}
	if c.Conn == nil {
		return nil, nil
	}
	people, _, err := c.people()
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, n := range c.idents {
		scopes := by[n.ID]
		held := people[n.ID]
		if len(scopes) == 0 || held == nil || held.OwnerID == nil {
			continue // no scope, or no owner: nhi-ownership reports the latter
		}
		bound := false
		for _, d := range scopes {
			bound = bound || d.Ceiling()
		}
		owner, ok := c.byID[*held.OwnerID]
		if !bound || !ok {
			continue
		}
		ownerEff := c.eff(owner.ID)
		ownerScopes := by[owner.ID] // an owner that is an agent with a scope lends that scope as the ceiling
		var bad []*graph.EffectivePermission
		for _, ep := range c.eff(n.ID).Values() {
			if !ownerEff.Has(ep.PermKey) || len(ownerScopes) > 0 && !permitted(ownerScopes, ep) {
				bad = append(bad, ep)
			}
		}
		if len(bad) == 0 {
			continue
		}
		msg := fmt.Sprintf("%s holds %d permission(s) its owner %s does not", n.Label, len(bad), owner.Label)
		out = append(out, agentFinding(p, c, n, fmt.Sprintf("%s:%d:owner", scopes[0].Key, n.ID), msg, scopes, bad))
	}
	return out, nil
}
