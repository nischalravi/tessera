package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// MCP resource bindings (issue #479): a tenant sees and changes only its own
// bindings; a binding that names another tenant's resource is refused by the
// guard trigger; the audience is unique per tenant, not across tenants.

func TestIsolation_MCPResourceBindings(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedMCP(t, f)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			// the same issuer and audience in both tenants is two separate rows
			return c.PutMCPResourceBinding(&store.MCPResourceBinding{ResourceID: ids[tn.Slug].resource, Issuer: "https://as.example/mcp",
				Audience: "https://mcp.example/aud", UpdatedBy: "admin", UpdatedAt: storetest.Now})
		})
		if err != nil {
			t.Fatalf("bind in %s: %v", tn.Slug, err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.MCPResourceBinding(ids[f.A.Slug].resource); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MCPResourceBinding(A's) = %v", err)
		}
		if b, err := c.MCPResourceBinding(ids[f.B.Slug].resource); err != nil || b.Audience != "https://mcp.example/aud" {
			t.Errorf("MCPResourceBinding(B's) = %+v, %v", b, err)
		}
		if bs, err := c.MCPResourceBindings(); err != nil || len(bs) != 1 || bs[0].ResourceID != ids[f.B.Slug].resource {
			t.Errorf("MCPResourceBindings = %v, %v", bs, err)
		}
		return nil
	})
	// B cannot bind A's resource, and an update never reaches A's row
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.PutMCPResourceBinding(&store.MCPResourceBinding{ResourceID: ids[f.A.Slug].resource, Issuer: "https://evil.example",
			Audience: "https://evil.example", UpdatedBy: "b", UpdatedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("binding A's resource from B = %v, want ErrCrossTenant", err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if b, err := c.MCPResourceBinding(ids[f.A.Slug].resource); err != nil || b.Issuer != "https://as.example/mcp" {
			t.Errorf("A's binding = %+v, %v", b, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// the audience is unique inside a tenant
	err = f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		other := &store.MCPResource{Resource: "https://mcp.example/second", Name: "second", SecretHash: storetestHash, CreatedBy: "admin", CreatedAt: storetest.Now}
		if err := c.InsertMCPResource(other); err != nil {
			return err
		}
		return c.PutMCPResourceBinding(&store.MCPResourceBinding{ResourceID: other.ID, Issuer: "https://as.example/mcp",
			Audience: "https://mcp.example/aud", UpdatedBy: "admin", UpdatedAt: storetest.Now})
	})
	if err == nil {
		t.Error("two resources of one tenant bound to one audience")
	}
}

func mcpBindingsCovered() map[string]bool {
	return map[string]bool{"PutMCPResourceBinding": true, "MCPResourceBinding": true, "MCPResourceBindings": true}
}
