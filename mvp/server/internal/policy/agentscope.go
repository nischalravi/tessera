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
// The scopes of an agent are those that name it (agent profile source and external id); only when none does, those of
// its blueprint (agent link blueprint app id) apply, so a broad blueprint scope never widens an agent's own narrower
// one. An agent is in scope when any of the scopes that apply allows the permission. An agent with no scope is not
// checked here: nhi-ownership and the agent views report it.
//
// The owner ceiling walks the owner chain to a person: every scoped agent on the way lends its scope as a further
// ceiling, and the person's effective permissions are the last one. When the chain does not end at an active person
// (no owner, an owner the graph does not know, a terminated owner, a cycle, or only agents), there is no ceiling to
// stay under, so every permission the agent holds is reported: a missing owner never turns the check off. Both findings come from the effective
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

// scoped maps an identity id to the scopes that apply to it, by key: the agent's own scopes, or its blueprint's when
// it has none of its own. agents is every identity with an agent profile.
func scoped(c *Context, docs []*agentscope.Doc) (out map[int64][]*agentscope.Doc, agents map[int64]bool, err error) {
	out, agents = map[int64][]*agentscope.Doc{}, map[int64]bool{}
	if c.Conn == nil {
		return out, agents, nil // the selectors need the database
	}
	profiles, err := c.Conn.AgentProfiles()
	if err != nil {
		return nil, nil, err
	}
	links, err := c.Conn.AgentLinks()
	if err != nil {
		return nil, nil, err
	}
	type key struct{ source, ext string }
	identity := map[key]int64{}
	for _, p := range profiles {
		identity[key{p.Source, p.ExternalID}] = p.IdentityID
		agents[p.IdentityID] = true
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
	for id, l := range out {
		own := l[:0:0]
		for _, d := range l {
			if !d.ByBlueprint() {
				own = append(own, d)
			}
		}
		if len(own) > 0 {
			l = own // the agent's own scope is its ceiling; the blueprint's is only the default
		}
		sort.SliceStable(l, func(i, j int) bool { return l[i].Key < l[j].Key })
		out[id] = l
	}
	return out, agents, nil
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
	by, _, err := scoped(c, p.AgentScopes)
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

// ceilingOf walks the owner chain of agent id to a person. It returns the person's node and the scopes of the agents
// on the way (each a further ceiling), or a reason when the chain does not end at an active person.
func ceilingOf(c *Context, id int64, people map[int64]*store.Identity, by map[int64][]*agentscope.Doc, agents map[int64]bool) (*graph.Node, [][]*agentscope.Doc, string) {
	var lent [][]*agentscope.Doc
	seen := map[int64]bool{id: true}
	for cur := id; ; {
		held := people[cur]
		if held == nil || held.OwnerID == nil {
			if cur == id {
				return nil, nil, "it has no owner"
			}
			return nil, nil, "its owner chain ends at an agent, not a person"
		}
		o := *held.OwnerID
		if seen[o] {
			return nil, nil, "its owner chain is a cycle"
		}
		seen[o] = true
		owner, ok := c.byID[o]
		if !ok || people[o] == nil {
			return nil, nil, "its owner is not in the graph"
		}
		if agents[o] {
			if s := by[o]; len(s) > 0 {
				lent = append(lent, s)
			}
			cur = o
			continue
		}
		if owner.Status == "terminated" {
			return nil, nil, "its owner " + owner.Label + " is terminated"
		}
		return owner, lent, ""
	}
}

func evalAgentExceedsOwner(p *Policy, c *Context) ([]Violation, error) {
	by, agents, err := scoped(c, p.AgentScopes)
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
		bound := false
		for _, d := range scopes {
			bound = bound || d.Ceiling()
		}
		if !bound {
			continue
		}
		owner, lent, reason := ceilingOf(c, n.ID, people, by, agents)
		var bad []*graph.EffectivePermission
		for _, ep := range c.eff(n.ID).Values() {
			ok := owner != nil && c.eff(owner.ID).Has(ep.PermKey)
			for _, s := range lent {
				ok = ok && permitted(s, ep)
			}
			if !ok {
				bad = append(bad, ep)
			}
		}
		if len(bad) == 0 {
			continue
		}
		msg := ""
		if owner != nil {
			msg = fmt.Sprintf("%s holds %d permission(s) its owner %s does not", n.Label, len(bad), owner.Label)
		} else {
			msg = fmt.Sprintf("%s holds %d permission(s) with no owner ceiling: %s", n.Label, len(bad), reason)
		}
		out = append(out, agentFinding(p, c, n, fmt.Sprintf("%s:%d:owner", scopes[0].Key, n.ID), msg, scopes, bad))
	}
	return out, nil
}
