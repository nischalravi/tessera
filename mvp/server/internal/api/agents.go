package api

import (
	"net/http"
	"sort"

	"github.com/nischalravi/tessera/mvp/server/internal/nhi"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// AI agent discovery (issue #116). Two read routes next to /api/nhi, whose
// response is unchanged:
//
//	GET /api/agents               the ai_agent inventory with where each agent came
//	                              from, who created and sponsors it, whether the
//	                              sponsor is active, and its violations
//	GET /api/agents/mcp-findings  MCP servers and agent credentials found in code
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
}

func (s *Server) listAgents(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
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

// findingView is one MCP server or credential found in source code.
type findingView struct {
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
	out := []findingView{}
	for _, f := range rows {
		if kind != nil && f.Kind != *kind {
			continue
		}
		v := findingView{ID: f.ID, Source: f.Source, Kind: f.Kind, Org: f.Org, Repo: f.Repo, Path: f.Path, Location: f.Location,
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
