package entra

// Entra Agent ID discovery (issue #116). Additive to the directory read: it
// runs only when Config.DiscoverAgents is set, and only reads.
//
// An Entra agent identity is a service principal of type
// microsoft.graph.agentIdentity. Microsoft Graph serves it from the beta
// endpoint only (at the time of writing), so this is the one place the
// connector uses /beta:
//
//	GET /beta/servicePrincipals/microsoft.graph.agentIdentity   the agent identities
//	GET /beta/servicePrincipals/{id}/microsoft.graph.agentIdentity/sponsors   its sponsors
//
// The shapes are those of the Graph documentation, exercised here against
// recorded fixtures only: this code has not been run against a live tenant.
// A 403 or 404 (no AgentIdentity.Read.All, or the tenant has no Agent ID) means
// no agents, not a failed sync.
//
// Mapping: the agent is an ai_agent identity ("entra-sp:<id>", the same key the
// service principal read uses, so the two never duplicate) owned by its first
// enabled sponsor (which is what the nhi-ownership policy checks), an account of
// kind agent, its password and key credentials as secrets (id, name and start
// date only, never the secret text or the hint), and an AgentRecord with the
// creator and sponsor as Entra spells them.

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// AgentKind is the AgentRecord kind of an Entra agent identity.
const AgentKind = "entra_agent_identity"

type eCredential struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
	Start       string `json:"startDateTime"`
	End         string `json:"endDateTime"`
}

type eSponsor struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	Mail           string `json:"mail"`
	UPN            string `json:"userPrincipalName"`
	AccountEnabled *bool  `json:"accountEnabled"`
}

type eAgent struct {
	ID                  string        `json:"id"`
	AppID               string        `json:"appId"`
	DisplayName         string        `json:"displayName"`
	AccountEnabled      *bool         `json:"accountEnabled"`
	CreatedByAppID      string        `json:"createdByAppId"`
	Created             string        `json:"createdDateTime"`
	PasswordCredentials []eCredential `json:"passwordCredentials"`
	KeyCredentials      []eCredential `json:"keyCredentials"`
	sponsors            []eSponsor
}

const agentSelect = "$select=id,appId,displayName,accountEnabled,createdByAppId,createdDateTime,passwordCredentials,keyCredentials&$top=999"

// graphBeta builds an absolute beta URL.
func (c *Connector) graphBeta(path, rawQuery string) string {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/beta" + path
	u.RawQuery = rawQuery
	return u.String()
}

// readAgents lists the agent identities and their sponsors. ok is false when
// Graph says the tenant has none to read (403, 404).
func (c *Connector) readAgents(ctx context.Context) (agents []*eAgent, ok bool, err error) {
	_, err = listAll(ctx, c, c.graphBeta("/servicePrincipals/microsoft.graph.agentIdentity", agentSelect), func(a eAgent) error {
		if validID(a.ID) {
			agents = append(agents, &a)
		}
		return nil
	})
	if err != nil {
		if s := connsync.Status(err); s == 403 || s == 404 {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("entra: agent identities: %w", err)
	}
	for _, a := range agents {
		path := "/servicePrincipals/" + url.PathEscape(a.ID) + "/microsoft.graph.agentIdentity/sponsors"
		_, err := listAll(ctx, c, c.graphBeta(path, "$select=id,displayName,mail,userPrincipalName,accountEnabled"), func(s eSponsor) error {
			a.sponsors = append(a.sponsors, s)
			return nil
		})
		if err != nil {
			// Sponsors unreadable (403/404): the agent has no known sponsor, which the
			// ownership policy then reports. Anything else fails the sync.
			if s := connsync.Status(err); s == 403 || s == 404 {
				a.sponsors = nil
				continue
			}
			return nil, false, fmt.Errorf("entra: agent sponsors: %w", err)
		}
	}
	sort.SliceStable(agents, func(i, j int) bool { return agents[i].ID < agents[j].ID })
	return agents, true, nil
}

// markAgents makes sure every agent is among the service principals, owned by
// this tenant, so the directory build emits its identity, account and edges.
func (c *Connector) markAgents(sps []*servicePrincipal, agents []*eAgent) []*servicePrincipal {
	have := map[string]*servicePrincipal{}
	for _, sp := range sps {
		have[sp.ID] = sp
	}
	for _, a := range agents {
		sp := have[a.ID]
		if sp == nil {
			sp = &servicePrincipal{ID: a.ID, AppID: a.AppID, DisplayName: a.DisplayName, AccountEnabled: a.AccountEnabled,
				Type: "agentIdentity"}
			sps = append(sps, sp)
		}
		sp.owned = true
	}
	return sps
}

func (s eSponsor) email() string {
	if s.Mail != "" {
		return s.Mail
	}
	if strings.Contains(s.UPN, "@") && !strings.Contains(s.UPN, "#EXT#") {
		return s.UPN
	}
	return ""
}

// applyAgents turns the service identity and account the directory build made
// for each agent into an ai_agent, and adds its credentials and provenance.
func (c *Connector) applyAgents(res *connectors.DiscoveryResult, agents []*eAgent) {
	byXID := map[string]*eAgent{}
	for _, a := range agents {
		byXID["entra-sp:"+a.ID] = a
	}
	have := map[string]bool{}
	for i := range res.Identities {
		id := &res.Identities[i]
		a := byXID[id.ExternalID]
		if a == nil {
			continue
		}
		have[id.ExternalID] = true
		id.Type = "ai_agent"
		id.Description = strp("Entra agent identity")
		id.Owner = activeSponsor(a)
	}
	for _, a := range agents {
		xid := "entra-sp:" + a.ID
		name := a.DisplayName
		if name == "" {
			name = a.ID
		}
		if !have[xid] { // identities are not emitted for service principals: the agent still needs one
			res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "ai_agent",
				Status: "active", Description: strp("Entra agent identity"), Owner: activeSponsor(a)})
		}
		for i := range res.Accounts {
			if res.Accounts[i].System == System && res.Accounts[i].ExternalID == a.ID {
				res.Accounts[i].Kind = "agent"
				res.Accounts[i].CreatedAt = parseTime(a.Created)
			}
		}
		acct := connectors.Ref{Kind: "account", System: System, ExternalID: a.ID}
		for _, cr := range a.PasswordCredentials {
			c.addCredential(res, a, acct, "client_secret", cr)
		}
		for _, cr := range a.KeyCredentials {
			c.addCredential(res, a, acct, "certificate", cr)
		}
		rec := connectors.AgentRecord{System: System, ExternalID: a.ID, Identity: connectors.IdentityRef{ExternalID: xid}, Kind: AgentKind}
		if a.CreatedByAppID != "" {
			rec.CreatorRef = "app:" + a.CreatedByAppID
		}
		if len(a.sponsors) > 0 {
			s := a.sponsors[0]
			rec.SponsorRef = s.email()
			if rec.SponsorRef == "" {
				rec.SponsorRef = s.DisplayName
			}
		}
		rec.Sponsor = activeSponsor(a)
		if rec.Sponsor != nil && rec.SponsorRef == "" {
			rec.SponsorRef = rec.Sponsor.Email
		}
		res.Agents = append(res.Agents, rec)
	}
	res.AgentSnapshotOf = append(res.AgentSnapshotOf, System)
}

// activeSponsor is the first sponsor whose Entra account is enabled and that
// has an e-mail address to correlate by; nil when there is none.
func activeSponsor(a *eAgent) *connectors.IdentityRef {
	for _, s := range a.sponsors {
		if s.AccountEnabled != nil && !*s.AccountEnabled {
			continue
		}
		if e := s.email(); e != "" {
			return &connectors.IdentityRef{Email: e}
		}
	}
	return nil
}

// addCredential records one credential as a secret: identifiers and dates only.
// An expired credential is not usable and is left out.
func (c *Connector) addCredential(res *connectors.DiscoveryResult, a *eAgent, acct connectors.Ref, kind string, cr eCredential) {
	if cr.KeyID == "" || len(cr.KeyID) > 64 {
		return
	}
	if end := parseTime(cr.End); end != nil && end.Before(c.now()) {
		return
	}
	created := parseTime(cr.Start)
	if created == nil {
		t := c.now()
		created = &t
	}
	name := cr.DisplayName
	if name == "" {
		name = kind
	}
	res.Secrets = append(res.Secrets, connectors.SecretRecord{System: System, ExternalID: a.ID + ":" + cr.KeyID, Account: acct,
		Kind: kind, Name: name, CreatedAt: *created})
}
