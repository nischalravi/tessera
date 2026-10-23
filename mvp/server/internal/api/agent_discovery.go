package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/nhi"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// AI agent discovery (issue #116). Two read routes next to /api/nhi, whose
// response is unchanged:
//
//	GET /api/ai-agents            the ai_agent inventory with where each agent came
//	                              from, who created and sponsors it, whether the
//	                              sponsor is active, and its violations
//	GET /api/ai-agents/mcp-findings  MCP servers and agent credentials found in code
//
// No response carries a secret value: credentials are counts and ages, findings
// are locations, types and fingerprints.

// agentView is one row of the agent inventory.
type agentView struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Status      string  `json:"status"`
	Description *string `json:"description"`
	// Source is the system the agent was discovered in; SourceKind says what it is there.
	Source     string  `json:"source"`
	SourceKind *string `json:"source_kind"`
	Creator    *string `json:"creator"`
	// Sponsor is the person responsible for the agent. SponsorStatus is active, inactive (the
	// sponsor has left or is disabled) or none; both are what the nhi-ownership policy checks.
	Sponsor       *nhi.Owner `json:"sponsor"`
	SponsorRef    *string    `json:"sponsor_ref"`
	SponsorStatus string     `json:"sponsor_status"`
	Systems       []string   `json:"systems"`
	Credentials   int        `json:"credentials"`
	// OldestSecretDays is the age of the oldest credential.
	OldestSecretDays      *int     `json:"oldest_secret_days"`
	EffectivePermissions  int      `json:"effective_permissions"`
	PrivilegedPermissions int      `json:"privileged_permissions"`
	Flags                 []string `json:"flags"`
	Risk                  int      `json:"risk"`
	Violations            []string `json:"violations"`
	FirstSeenAt           *string  `json:"first_seen_at"`
	LastSeenAt            *string  `json:"last_seen_at"`
	// Blueprint (Entra Agent ID) is the template the agent was created from, matched on the
	// blueprint's appId. ManagerApplications are the application ids that manage the agent
	// (applications, not people; humans are sponsors and owners). Flags carries "no_sponsor"
	// when the agent has no sponsor at all (issue #478).
	Blueprint           *blueprintRef `json:"blueprint"`
	ManagerApplications []string      `json:"manager_applications"`
}

type blueprintRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// blueprintView is one row of the agent blueprint inventory.
type blueprintView struct {
	Source        string     `json:"source"`
	ID            string     `json:"id"` // the blueprint's object id; agents link by app_id
	AppID         *string    `json:"app_id"`
	Name          string     `json:"name"`
	Creator       *string    `json:"creator"`
	Sponsor       *nhi.Owner `json:"sponsor"`
	SponsorRef    *string    `json:"sponsor_ref"`
	SponsorStatus string     `json:"sponsor_status"` // active | inactive | none
	Agents        int        `json:"agents"`
	FirstSeenAt   string     `json:"first_seen_at"`
	LastSeenAt    string     `json:"last_seen_at"`
}

func ownerOf(people map[int64]*store.Identity, id *int64) *nhi.Owner {
	if id == nil {
		return nil
	}
	o := people[*id]
	if o == nil {
		return nil
	}
	return &nhi.Owner{ID: o.ID, Name: o.Name, Status: o.Status, Department: o.Department}
}

func sponsorStatus(o *nhi.Owner) string {
	switch {
	case o == nil:
		return "none"
	case o.Status == "active":
		return "active"
	}
	return "inactive"
}

func (s *Server) listAgentBlueprints(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	people, _, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	bps, err := c.AgentBlueprints()
	if err != nil {
		return nil, err
	}
	links, err := c.AgentLinks()
	if err != nil {
		return nil, err
	}
	agents := map[[2]string]int{}
	for _, l := range links {
		if l.BlueprintAppID != "" {
			agents[[2]string{l.Source, l.BlueprintAppID}]++
		}
	}
	out := []blueprintView{}
	for _, b := range bps {
		sp := ownerOf(people, b.SponsorID)
		out = append(out, blueprintView{Source: b.Source, ID: b.ExternalID, AppID: nonEmptyPtr(b.AppID), Name: b.Name,
			Creator: nonEmptyPtr(b.CreatorRef), Sponsor: sp, SponsorRef: nonEmptyPtr(b.SponsorRef), SponsorStatus: sponsorStatus(sp),
			Agents: agents[[2]string{b.Source, b.AppID}], FirstSeenAt: timeutil.ISO(b.FirstSeenAt), LastSeenAt: timeutil.ISO(b.LastSeenAt)})
	}
	return out, nil
}

func (s *Server) listAIAgents(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	items, err := nhi.Inventory(a.c, a.g, a.u)
	if err != nil {
		return nil, err
	}
	profiles, err := a.c.AgentProfiles()
	if err != nil {
		return nil, err
	}
	byIdentity := map[int64]*store.AgentProfile{}
	for _, pr := range profiles {
		byIdentity[pr.IdentityID] = pr
	}
	bps, err := a.c.AgentBlueprints()
	if err != nil {
		return nil, err
	}
	links, err := a.c.AgentLinks()
	if err != nil {
		return nil, err
	}
	blueprintName := map[[2]string]string{} // by the blueprint's appId, which agents carry
	for _, b := range bps {
		if b.AppID != "" {
			blueprintName[[2]string{b.Source, b.AppID}] = b.Name
		}
	}
	linkOf := map[[2]string]*store.AgentLink{}
	for _, l := range links {
		linkOf[[2]string{l.Source, l.ExternalID}] = l
	}
	viol, err := a.violations()
	if err != nil {
		return nil, err
	}
	policiesOf := map[int64][]string{}
	for _, v := range viol {
		if v.IdentityID != nil {
			policiesOf[*v.IdentityID] = append(policiesOf[*v.IdentityID], v.PolicyID)
		}
	}
	out := []agentView{}
	for _, it := range items {
		if it.Type != "ai_agent" {
			continue
		}
		v := agentView{ID: it.ID, Name: it.Name, Status: it.Status, Description: it.Description, Source: "unknown",
			Sponsor: it.Owner, SponsorStatus: "none", Systems: it.Systems, Credentials: len(it.Secrets),
			OldestSecretDays: it.OldestSecretDays, EffectivePermissions: it.EffectivePermissions,
			PrivilegedPermissions: it.PrivilegedPermissions, Flags: it.Flags, Risk: it.Risk, Violations: []string{}}
		if len(it.Systems) > 0 {
			v.Source = it.Systems[0]
		}
		if it.Owner != nil {
			v.SponsorStatus = "inactive"
			if it.Owner.Status == "active" {
				v.SponsorStatus = "active"
			}
		}
		if pr := byIdentity[it.ID]; pr != nil {
			v.Source, v.SourceKind = pr.Source, &pr.Kind
			v.Creator, v.SponsorRef = nonEmptyPtr(pr.CreatorRef), nonEmptyPtr(pr.SponsorRef)
			v.FirstSeenAt, v.LastSeenAt = timeutil.ISOPtr(&pr.FirstSeenAt), timeutil.ISOPtr(&pr.LastSeenAt)
			if l := linkOf[[2]string{pr.Source, pr.ExternalID}]; l != nil {
				if l.BlueprintAppID != "" {
					name := blueprintName[[2]string{pr.Source, l.BlueprintAppID}]
					if name == "" {
						name = l.BlueprintAppID
					}
					v.Blueprint = &blueprintRef{ID: l.BlueprintAppID, Name: name}
				}
				if l.ManagerApplications != "" {
					v.ManagerApplications = strings.Split(l.ManagerApplications, ",")
				}
			}
		}
		// No sponsor at all (neither an identity nor a name from the source) is its own flag;
		// a sponsor who left is "inactive" and is reported by nhi-ownership.
		if v.SponsorStatus == "none" && v.SponsorRef == nil {
			v.Flags = append(append([]string{}, v.Flags...), "no_sponsor")
		}
		if ps := policiesOf[it.ID]; len(ps) > 0 {
			sort.Strings(ps)
			v.Violations = ps
		}
		out = append(out, v)
	}
	return out, nil
}

func nonEmptyPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// findingOwner is who a finding is linked to: how it was found, the name the
// source gave, and the Tessera identity when that resolved to one.
type findingOwner struct {
	Source   string     `json:"source"` // codeowners | committer | none
	Ref      *string    `json:"ref"`
	Identity *nhi.Owner `json:"identity"`
}

// mcpFindingView is one MCP server or credential found in source code.
type mcpFindingView struct {
	ID          int64        `json:"id"`
	Source      string       `json:"source"`
	Kind        string       `json:"kind"`
	Org         string       `json:"org"`
	Repo        string       `json:"repo"`
	Path        string       `json:"path"`
	Location    string       `json:"location"`
	Server      *string      `json:"server"`
	Transport   *string      `json:"transport"`
	Target      *string      `json:"target"`
	SecretType  *string      `json:"secret_type"`
	Fingerprint *string      `json:"fingerprint"`
	Owner       findingOwner `json:"owner"`
	CommitSHA   *string      `json:"commit_sha"`
	FirstSeenAt string       `json:"first_seen_at"`
	LastSeenAt  string       `json:"last_seen_at"`
}

func (s *Server) listMCPFindings(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	kind := p.queryOptLiteral("kind", []string{"mcp_server", "agent_credential"})
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	people, _, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	rows, err := c.MCPFindings()
	if err != nil {
		return nil, err
	}
	out := []mcpFindingView{}
	for _, f := range rows {
		if kind != nil && f.Kind != *kind {
			continue
		}
		v := mcpFindingView{ID: f.ID, Source: f.Source, Kind: f.Kind, Org: f.Org, Repo: f.Repo, Path: f.Path, Location: f.Location,
			Server: nonEmptyPtr(f.Server), Transport: nonEmptyPtr(f.Transport), Target: nonEmptyPtr(f.Target),
			SecretType: nonEmptyPtr(f.SecretType), Fingerprint: nonEmptyPtr(f.Fingerprint), CommitSHA: nonEmptyPtr(f.CommitSHA),
			Owner:       findingOwner{Source: f.OwnerSource, Ref: nonEmptyPtr(f.OwnerRef)},
			FirstSeenAt: timeutil.ISO(f.FirstSeenAt), LastSeenAt: timeutil.ISO(f.LastSeenAt)}
		if f.OwnerID != nil {
			if o := people[*f.OwnerID]; o != nil {
				v.Owner.Identity = &nhi.Owner{ID: o.ID, Name: o.Name, Status: o.Status, Department: o.Department}
			}
		}
		out = append(out, v)
	}
	return out, nil
}
