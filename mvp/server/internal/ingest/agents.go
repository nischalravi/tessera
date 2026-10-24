package ingest

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// findingKey is a finding's natural key.
type findingKey struct{ source, kind, org, repo, path, location, fingerprint string }

// agentDiscovery stores the agent profiles and MCP findings of the results
// (issue #116) and removes what a complete snapshot no longer lists. It runs
// after every identity exists, so creators, sponsors and owners resolve.
func agentDiscovery(c *store.TenantTx, now time.Time, results []*connectors.DiscoveryResult, st *DiscoveryStats) error {
	var systems []string
	for _, r := range results {
		for _, s := range r.AgentSnapshotOf {
			if !slices.Contains(systems, s) {
				systems = append(systems, s)
			}
		}
	}
	var bpSystems []string
	for _, r := range results {
		bpSystems = append(bpSystems, r.BlueprintSnapshotOf...)
	}
	have := len(systems) > 0
	for _, r := range results {
		have = have || len(r.Agents) > 0 || len(r.MCPFindings) > 0 || len(r.Blueprints) > 0
	}
	if !have {
		return nil
	}
	res, err := NewResolver(c)
	if err != nil {
		return err
	}
	seenProfile := map[[2]string]bool{}
	for _, r := range results {
		for _, a := range r.Agents {
			id := res.Identity(&a.Identity)
			if id == nil {
				return fmt.Errorf("agent %s/%s references unknown identity %v", a.System, a.ExternalID, a.Identity)
			}
			creator, sponsor := res.Identity(a.Creator), res.Identity(a.Sponsor)
			if err := c.UpsertAgentProfile(&store.AgentProfile{Source: a.System, ExternalID: a.ExternalID, IdentityID: *id,
				Kind: a.Kind, CreatorRef: a.CreatorRef, CreatorID: creator, SponsorRef: a.SponsorRef, SponsorID: sponsor}, now); err != nil {
				return err
			}
			seenProfile[[2]string{a.System, a.ExternalID}] = true
			st.Agents++
			link := store.AgentLink{Source: a.System, ExternalID: a.ExternalID, BlueprintAppID: a.BlueprintAppID,
				ManagerApplications: strings.Join(a.ManagerApplications, ",")}
			if link.BlueprintAppID == "" && link.ManagerApplications == "" {
				err = c.DeleteAgentLink(a.System, a.ExternalID)
			} else {
				err = c.UpsertAgentLink(&link)
			}
			if err != nil {
				return err
			}
		}
	}
	seenBlueprint := map[[2]string]bool{}
	for _, r := range results {
		for _, b := range r.Blueprints {
			if err := c.UpsertAgentBlueprint(&store.AgentBlueprint{Source: b.System, ExternalID: b.ExternalID, AppID: b.AppID,
				Name: b.Name, CreatorRef: b.CreatorRef, SponsorRef: b.SponsorRef, SponsorID: res.Identity(b.Sponsor)}, now); err != nil {
				return err
			}
			seenBlueprint[[2]string{b.System, b.ExternalID}] = true
		}
	}
	blueprints, err := c.AgentBlueprints()
	if err != nil {
		return err
	}
	for _, b := range blueprints {
		if slices.Contains(bpSystems, b.Source) && !seenBlueprint[[2]string{b.Source, b.ExternalID}] {
			if err := c.DeleteAgentBlueprint(b.Source, b.ExternalID); err != nil {
				return err
			}
		}
	}
	profiles, err := c.AgentProfiles()
	if err != nil {
		return err
	}
	for _, p := range profiles {
		if slices.Contains(systems, p.Source) && !seenProfile[[2]string{p.Source, p.ExternalID}] {
			if err := c.DeleteAgentProfile(p.Source, p.ExternalID); err != nil {
				return err
			}
			if err := c.DeleteAgentLink(p.Source, p.ExternalID); err != nil {
				return err
			}
		}
	}
	seenFinding := map[findingKey]bool{}
	for _, r := range results {
		for _, f := range r.MCPFindings {
			if err := c.UpsertMCPFinding(&store.MCPFinding{Source: f.System, Kind: f.Kind, Org: f.Org, Repo: f.Repo, Path: f.Path,
				Location: f.Location, Server: f.Server, Transport: f.Transport, Target: f.Target, SecretType: f.SecretType,
				Fingerprint: f.Fingerprint, OwnerRef: f.OwnerRef, OwnerSource: defaultStr(f.OwnerSource, "none"),
				OwnerID: res.Identity(f.Owner), CommitSHA: f.CommitSHA}, now); err != nil {
				return err
			}
			seenFinding[findingKey{f.System, f.Kind, f.Org, f.Repo, f.Path, f.Location, f.Fingerprint}] = true
			st.MCPFindings++
		}
	}
	findings, err := c.MCPFindings()
	if err != nil {
		return err
	}
	for _, f := range findings {
		if slices.Contains(systems, f.Source) && !seenFinding[findingKey{f.Source, f.Kind, f.Org, f.Repo, f.Path, f.Location, f.Fingerprint}] {
			if err := c.DeleteMCPFinding(f.ID); err != nil {
				return err
			}
		}
	}
	return nil
}
