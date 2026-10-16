package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// AI agent discovery (issue #116): a tenant sees, replaces and deletes only
// its own agent profiles and findings, even for the same source and key, and
// neither table can point at another tenant's identity.

func agentsCovered() map[string]bool {
	return map[string]bool{"AgentProfiles": true, "UpsertAgentProfile": true, "DeleteAgentProfile": true, // TestIsolation_AgentProfiles*
		"MCPFindings": true, "UpsertMCPFinding": true, "DeleteMCPFinding": true} // TestIsolation_MCPFindings*
}

func seedAgents(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			me := tn.IDs["alice"]
			if err := c.UpsertAgentProfile(&store.AgentProfile{Source: "entra", ExternalID: "agent-1", IdentityID: me,
				Kind: "entra_agent_identity", CreatorRef: "creator-" + tn.Slug, SponsorRef: "sponsor-" + tn.Slug, SponsorID: &me},
				storetest.Now); err != nil {
				return err
			}
			return c.UpsertMCPFinding(&store.MCPFinding{Source: "github", Kind: "agent_credential", Org: "acme", Repo: "svc",
				Path: ".mcp.json", Location: "mcpServers.x.env.TOKEN", SecretType: "github_token", Fingerprint: "fp-" + tn.Slug,
				OwnerRef: "owner-" + tn.Slug, OwnerSource: "codeowners", OwnerID: &me}, storetest.Now)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// The shared fixture seeds profiles and findings of its own (source okta and
// github-scan); these tests look at the rows seedAgents adds.
func entraProfiles(c *store.TenantTx) (out []*store.AgentProfile, err error) {
	all, err := c.AgentProfiles()
	for _, p := range all {
		if p.Source == "entra" {
			out = append(out, p)
		}
	}
	return out, err
}

func githubFindings(c *store.TenantTx) (out []*store.MCPFinding, err error) {
	all, err := c.MCPFindings()
	for _, f := range all {
		if f.Source == "github" {
			out = append(out, f)
		}
	}
	return out, err
}

func TestIsolation_AgentProfilesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedAgents(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		ps, err := entraProfiles(c)
		if err != nil || len(ps) != 1 || ps[0].CreatorRef != "creator-"+f.B.Slug || ps[0].IdentityID != f.B.IDs["alice"] {
			t.Errorf("B's profiles = %+v, %v", ps, err)
		}
		// B deletes "its" entra/agent-1: A's survives.
		return c.DeleteAgentProfile("entra", "agent-1")
	})
	inA(t, f, func(c *store.TenantTx) error {
		ps, err := entraProfiles(c)
		if err != nil || len(ps) != 1 || ps[0].CreatorRef != "creator-"+f.A.Slug {
			t.Errorf("A's profiles = %+v, %v", ps, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if ps, err := entraProfiles(c); err != nil || len(ps) != 0 {
			t.Errorf("B's profiles after delete = %+v, %v", ps, err)
		}
		return nil
	})
}

func TestIsolation_MCPFindingsScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedAgents(t, f)
	var aID int64
	inA(t, f, func(c *store.TenantTx) error {
		fs, err := githubFindings(c)
		if err != nil || len(fs) != 1 || fs[0].Fingerprint != "fp-"+f.A.Slug {
			t.Fatalf("A's findings = %+v, %v", fs, err)
		}
		aID = fs[0].ID
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		fs, err := githubFindings(c)
		if err != nil || len(fs) != 1 || fs[0].Fingerprint != "fp-"+f.B.Slug || fs[0].ID == aID {
			t.Errorf("B's findings = %+v, %v", fs, err)
		}
		// A's finding id is not reachable from B.
		if err := c.DeleteMCPFinding(aID); err != nil {
			t.Errorf("delete by foreign id: %v", err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if fs, err := githubFindings(c); err != nil || len(fs) != 1 {
			t.Errorf("A's findings after B's delete = %+v, %v", fs, err)
		}
		return nil
	})
}

func TestIsolation_AgentDiscoveryRefusesForeignIdentity(t *testing.T) {
	f := storetest.TwoTenants(t)
	foreign := f.A.IDs["alice"]
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.UpsertAgentProfile(&store.AgentProfile{Source: "okta", ExternalID: "x", IdentityID: foreign, Kind: "okta_service_app"},
			storetest.Now)
	})
	if err == nil {
		t.Error("B stored a profile for A's identity")
	}
	err = f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.UpsertMCPFinding(&store.MCPFinding{Source: "github", Kind: "mcp_server", Org: "o", Repo: "r", Path: "p",
			Location: "l", OwnerID: &foreign}, storetest.Now)
	})
	if err == nil {
		t.Error("B stored a finding owned by A's identity")
	}
	inB(t, f, func(c *store.TenantTx) error {
		ps, _ := c.AgentProfiles()
		for _, p := range ps {
			if p.ExternalID == "x" {
				t.Errorf("profile = %+v", p)
			}
		}
		if _, err := c.Identity(foreign); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B sees A's identity: %v", err)
		}
		return nil
	})
}
