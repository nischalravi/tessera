// Package agentmap turns the agents of an AI agent platform into Tessera's graph (issue #562): each agent is an
// ai_agent non-human identity with an account and an agent profile, linked to its owner (the sponsor), and
// everything it can reach (a tool, an action, a knowledge source, the identity it runs as) is a permission
// granted to that account. The platform connectors read their API into Agent values; this package is the one
// mapping, so every platform links and flags the same way.
//
// Nothing here carries free text from the platform: prompts, instructions and descriptions are never read into
// an Agent, so they cannot be stored or reach a reviewer's screen.
package agentmap

import (
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
)

var emailRE = regexp.MustCompile(`^[^@\s/]{1,200}@[A-Za-z0-9.-]{1,253}$`)

// Person reads an owner or creator value: a ref for an e-mail address (lower-cased), and always the text kept
// as the source's own word for it.
func Person(v string) (*connectors.IdentityRef, string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, ""
	}
	if emailRE.MatchString(v) {
		return &connectors.IdentityRef{Email: strings.ToLower(v)}, v
	}
	return nil, Clip(v, 256)
}

// First returns the first non-empty value of keys in m (keys are lower-case).
func First(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

// Clip keeps at most n bytes of printable characters.
func Clip(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			break
		}
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Access is one thing an agent can reach.
type Access struct {
	// Resource is the resource's external id; Name and Kind describe it.
	Resource, Name, Kind string
	// Action is the permission (invoke, retrieve, run_as ...).
	Action string
	// Privileged marks code execution and the like.
	Privileged bool
	// Tags are added to the resource.
	Tags []string
}

// Agent is one agent and what is known about it.
type Agent struct {
	// ID is the agent's id in the platform; Name its display name; Kind the agent profile kind.
	ID, Name, Kind string
	// Disabled marks an agent that is switched off or failed.
	Disabled bool
	// Owner and Creator are the people's own words (an e-mail address links; anything else is kept as text).
	Owner, Creator string
	Created        time.Time
	// Attributes are non-secret account attributes.
	Attributes map[string]string
	// PII marks everything the agent reaches as holding personal data (the ai-agents-no-pii policy).
	PII bool
	// Tags are added to every resource the agent reaches.
	Tags   []string
	Access []Access
}

// Build maps the agents of one system. idPrefix gives the identity id ("vertex:" + the agent id) and what is
// the fixed description of every identity ("Vertex AI Agent Engine agent"). The result is a complete snapshot
// of the system's agents: one that is not listed again is gone.
func Build(system, idPrefix, what string, agents []Agent) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{AgentSnapshotOf: []string{system}}
	seenRes, seenPerm := map[string]bool{}, map[string]bool{}
	for _, a := range agents {
		xid := idPrefix + a.ID
		name := a.Name
		if name == "" {
			name = a.ID
		}
		status := "active"
		if a.Disabled {
			status = "disabled"
		}
		sponsor, sponsorRef := Person(a.Owner)
		creator, creatorRef := Person(a.Creator)
		desc := what
		res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "ai_agent", Status: status,
			Description: &desc, Owner: sponsor})
		var created *time.Time
		if !a.Created.IsZero() {
			t := a.Created.UTC()
			created = &t
		}
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: system, ExternalID: a.ID, Username: name,
			Identity: &connectors.IdentityRef{ExternalID: xid}, Kind: "agent", Status: status, CreatedAt: created, Attributes: a.Attributes})
		res.Agents = append(res.Agents, connectors.AgentRecord{System: system, ExternalID: a.ID, Identity: connectors.IdentityRef{ExternalID: xid},
			Kind: a.Kind, Creator: creator, CreatorRef: creatorRef, Sponsor: sponsor, SponsorRef: sponsorRef})
		acct := connectors.Ref{Kind: "account", System: system, ExternalID: a.ID}
		base := append([]string(nil), a.Tags...)
		if a.PII {
			base = append(base, "pii")
		}
		for _, x := range a.Access {
			if !seenRes[x.Resource] {
				seenRes[x.Resource] = true
				res.Resources = append(res.Resources, connectors.ResourceRecord{System: system, ExternalID: x.Resource, Name: x.Name, Kind: x.Kind,
					Tags: append(append([]string(nil), base...), x.Tags...)})
			}
			perm := x.Resource + "#" + x.Action
			if !seenPerm[perm] {
				seenPerm[perm] = true
				res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: system, ExternalID: perm, Action: x.Action,
					ResourceExternalID: x.Resource, Privileged: x.Privileged})
			}
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: acct, Dst: connectors.Ref{Kind: "perm", System: system, ExternalID: perm}, Relation: "direct_grant"})
		}
	}
	return res
}
