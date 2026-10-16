package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// MCP authorization server tables (issue #115): a tenant sees and changes
// only its own resources, clients, requests, tokens, decisions and replay
// entries; a row naming another tenant's identity is refused by the guard
// triggers.

type mcpSeed struct{ resource, request, jti string }

func seedMCP(t *testing.T, f *storetest.Fixture) map[string]mcpSeed {
	t.Helper()
	out := map[string]mcpSeed{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		s := mcpSeed{jti: "jti-" + tn.Slug}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			r := &store.MCPResource{Resource: "https://mcp.example/" + tn.Slug, Name: "mcp", SecretHash: storetestHash,
				CreatedBy: "admin", CreatedAt: storetest.Now}
			if err := c.InsertMCPResource(r); err != nil {
				return err
			}
			s.resource = r.ID
			cl := &store.MCPClient{ClientID: "https://client.example/" + tn.Slug + ".json", Name: "client", RedirectURIs: `["https://client.example/cb"]`,
				JWKS: `{"keys":[]}`, DocSHA256: storetestHash, ExpiresAt: storetest.Now.Add(time.Hour)}
			if err := c.UpsertMCPClient(cl, storetest.Now); err != nil {
				return err
			}
			agent := tn.IDs["helper-bot"]
			if err := c.SetMCPClient(cl.ClientID, &agent, "active", storetest.Now); err != nil {
				return err
			}
			a := &store.MCPAuthRequest{ClientID: cl.ClientID, RedirectURI: "https://client.example/cb", CodeChallenge: "x",
				Resource: r.Resource, Scope: "a:b:c", UserIdentity: tn.IDs["alice"], CreatedAt: storetest.Now,
				ExpiresAt: storetest.Now.Add(time.Hour)}
			if err := c.InsertMCPAuthRequest(a); err != nil {
				return err
			}
			s.request = a.ID
			if err := c.InsertMCPToken(&store.MCPToken{JTI: s.jti, ClientID: cl.ClientID, SubjectID: tn.IDs["alice"], AgentID: agent,
				Audience: r.Resource, Scope: "a:b:c", Act: "null", GrantType: "token_exchange", PolicyVersion: "pol-1",
				IssuedAt: storetest.Now, ExpiresAt: storetest.Now.Add(5 * time.Minute)}); err != nil {
				return err
			}
			if err := c.InsertMCPDecision(&store.MCPDecision{At: storetest.Now, Kind: store.MCPDecisionIssue, Allow: true, JTI: s.jti,
				PolicyVersion: "pol-1"}); err != nil {
				return err
			}
			fresh, err := c.UseMCPActorJTI(storetestHash, storetest.Now.Add(time.Minute), storetest.Now)
			if err != nil || !fresh {
				t.Errorf("UseMCPActorJTI in %s = %v, %v", tn.Slug, fresh, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = s
	}
	return out
}

const storetestHash = "0123456789012345678901234567890123456789012345678901234567890123"

func TestIsolation_MCPReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedMCP(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		if rs, err := c.MCPResources(); err != nil || len(rs) != 1 || rs[0].ID != ids[f.B.Slug].resource {
			t.Errorf("MCPResources = %v, %v", rs, err)
		}
		if _, err := c.MCPResource(ids[f.A.Slug].resource); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MCPResource(A's) = %v", err)
		}
		if _, err := c.MCPResourceByURI("https://mcp.example/" + f.A.Slug); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MCPResourceByURI(A's) = %v", err)
		}
		if cs, err := c.MCPClients(); err != nil || len(cs) != 1 {
			t.Errorf("MCPClients = %v, %v", cs, err)
		}
		if _, err := c.MCPClient("https://client.example/" + f.A.Slug + ".json"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MCPClient(A's) = %v", err)
		}
		if _, err := c.MCPAuthRequest(ids[f.A.Slug].request); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MCPAuthRequest(A's) = %v", err)
		}
		if _, err := c.MCPAuthRequestByCode(storetestHash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MCPAuthRequestByCode = %v", err)
		}
		if ts, err := c.MCPTokens(); err != nil || len(ts) != 1 || ts[0].JTI != ids[f.B.Slug].jti {
			t.Errorf("MCPTokens = %v, %v", ts, err)
		}
		if _, err := c.MCPToken(ids[f.A.Slug].jti); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MCPToken(A's) = %v", err)
		}
		if ds, err := c.MCPDecisions(10); err != nil || len(ds) != 1 || ds[0].JTI != ids[f.B.Slug].jti {
			t.Errorf("MCPDecisions = %v, %v", ds, err)
		}
		// the same assertion hash is a separate entry per tenant
		if fresh, err := c.UseMCPActorJTI(storetestHash, storetest.Now.Add(time.Minute), storetest.Now); err != nil || fresh {
			t.Errorf("replay of B's own jti = %v, %v", fresh, err)
		}
		return nil
	})
}

func TestIsolation_MCPWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedMCP(t, f)
	now := storetest.Now
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.RevokeMCPToken(ids[f.A.Slug].jti, "x", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("revoke of A's token in B = %v, want ErrNotFound", err)
		}
		if n, err := c.RevokeMCPTokensOfIdentity(f.A.IDs["helper-bot"], "x", now); err != nil || n != 0 {
			t.Errorf("RevokeMCPTokensOfIdentity(A's agent) in B = %d, %v", n, err)
		}
		if n, err := c.RevokeMCPTokensOfClient("https://client.example/"+f.A.Slug+".json", "x", now); err != nil || n != 0 {
			t.Errorf("RevokeMCPTokensOfClient(A's) in B = %d, %v", n, err)
		}
		if n, err := c.RevokeMCPTokensOfAudience("https://mcp.example/"+f.A.Slug, "x", now); err != nil || n != 0 {
			t.Errorf("RevokeMCPTokensOfAudience(A's) in B = %d, %v", n, err)
		}
		if err := c.SetMCPResourceStatus(ids[f.A.Slug].resource, "disabled"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetMCPResourceStatus(A's) = %v", err)
		}
		if err := c.SetMCPClient("https://client.example/"+f.A.Slug+".json", nil, "disabled", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetMCPClient(A's) = %v", err)
		}
		if err := c.RedeemMCPAuthRequest(ids[f.A.Slug].request); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RedeemMCPAuthRequest(A's) = %v", err)
		}
		if err := c.DecideMCPAuthRequest(ids[f.A.Slug].request, store.MCPAuthDenied, nil, "", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DecideMCPAuthRequest(A's) = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		tok, err := c.MCPToken(ids[f.A.Slug].jti)
		if err != nil || tok.RevokedAt != nil {
			t.Errorf("A's token = %+v, %v", tok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIsolation_MCPCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedMCP(t, f)
	now := storetest.Now
	cases := map[string]func(c *store.TenantTx) error{
		"client bound to A's agent": func(c *store.TenantTx) error {
			a := f.A.IDs["helper-bot"]
			return c.SetMCPClient("https://client.example/"+f.B.Slug+".json", &a, "active", now)
		},
		"auth request for A's user": func(c *store.TenantTx) error {
			return c.InsertMCPAuthRequest(&store.MCPAuthRequest{ClientID: "x", RedirectURI: "https://x/cb", CodeChallenge: "x",
				Resource: "https://x", Scope: "a:b:c", UserIdentity: f.A.IDs["alice"], CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
		},
		"token for A's subject": func(c *store.TenantTx) error {
			return c.InsertMCPToken(&store.MCPToken{JTI: "evil1", ClientID: "x", SubjectID: f.A.IDs["alice"], AgentID: f.B.IDs["helper-bot"],
				Audience: "https://x", Scope: "a:b:c", Act: "null", GrantType: "token_exchange", PolicyVersion: "p", IssuedAt: now,
				ExpiresAt: now.Add(time.Minute)})
		},
		"token for A's agent": func(c *store.TenantTx) error {
			return c.InsertMCPToken(&store.MCPToken{JTI: "evil2", ClientID: "x", SubjectID: f.B.IDs["alice"], AgentID: f.A.IDs["helper-bot"],
				Audience: "https://x", Scope: "a:b:c", Act: "null", GrantType: "token_exchange", PolicyVersion: "p", IssuedAt: now,
				ExpiresAt: now.Add(time.Minute)})
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
}

func mcpCovered() map[string]bool {
	return map[string]bool{"InsertMCPResource": true, "MCPResources": true, "MCPResource": true, "MCPResourceByURI": true,
		"SetMCPResourceStatus": true, "UpsertMCPClient": true, "MCPClient": true, "MCPClients": true, "SetMCPClient": true,
		"InsertMCPAuthRequest": true, "MCPAuthRequest": true, "MCPAuthRequestByCode": true, "DecideMCPAuthRequest": true,
		"RedeemMCPAuthRequest": true, "InsertMCPToken": true, "MCPToken": true, "MCPTokens": true, "RevokeMCPToken": true,
		"RevokeMCPTokensOfIdentity": true, "RevokeMCPTokensOfClient": true, "RevokeMCPTokensOfAudience": true,
		"InsertMCPDecision": true, "MCPDecisions": true, "UseMCPActorJTI": true}
}
