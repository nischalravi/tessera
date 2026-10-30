package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Agent scope isolation (issue #653, AC-7): a tenant sees and changes only its own scopes and their versions;
// another tenant's ids look nonexistent, a key is unique per tenant, and a version naming another tenant's scope is
// refused.

func seedAgentScope(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) string {
	t.Helper()
	id := "scope-" + tag
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		if err := c.InsertAgentScope(&store.AgentScope{ID: id, Key: "bot", Status: store.AgentScopeActive, Name: "Bot " + tag,
			Doc: `{"key":"bot"}`, DocSHA256: "d-" + tag, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		ref := `{"commit":"c-` + tag + `"}`
		return c.AddAgentScopeVersion(&store.AgentScopeVersion{ScopeID: id, Version: 1, Snapshot: "{}", Actor: "x",
			ChangedAt: storetest.Now, PolicyRef: &ref})
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIsolation_AgentScopes(t *testing.T) {
	f := storetest.TwoTenants(t)
	// the same key in both tenants is allowed: the unique index starts with the tenant
	a, b := seedAgentScope(t, f.DB, f.A, "a"), seedAgentScope(t, f.DB, f.B, "b")
	inB(t, f, func(c *store.TenantTx) error {
		ss, err := c.AgentScopes()
		if err != nil || len(ss) != 1 || ss[0].ID != b || ss[0].Name != "Bot b" {
			t.Errorf("AgentScopes = %+v, %v; want only B's", ss, err)
		}
		if s, err := c.AgentScopeByKey("bot"); err != nil || s.ID != b {
			t.Errorf("AgentScopeByKey = %+v, %v; want B's", s, err)
		}
		if _, err := c.AgentScopeByKey("nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AgentScopeByKey(missing) = %v", err)
		}
		if vs, err := c.AgentScopeVersions(a); err != nil || len(vs) != 0 {
			t.Errorf("AgentScopeVersions(A's) = %v, %v", vs, err)
		}
		if vs, err := c.AgentScopeVersions(b); err != nil || len(vs) != 1 || vs[0].PolicyRef == nil || *vs[0].PolicyRef != `{"commit":"c-b"}` {
			t.Errorf("AgentScopeVersions(B's) = %v, %v", vs, err)
		}
		return nil
	})
}

func TestIsolation_AgentScopeWrites(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := seedAgentScope(t, f.DB, f.A, "a")
	seedAgentScope(t, f.DB, f.B, "b")
	ctx := context.Background()
	// B cannot save A's scope (the id looks nonexistent), nor insert a duplicate key
	err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.SaveAgentScope(&store.AgentScope{ID: a, Status: store.AgentScopeRetired, Name: "x", Doc: "{}", DocSHA256: "x",
			Version: 2, UpdatedAt: storetest.Now}, 1)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("B saved A's scope: %v", err)
	}
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAgentScope(&store.AgentScope{Key: "bot", Status: store.AgentScopeActive, Name: "again", Doc: "{}",
			DocSHA256: "x", Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("a duplicate key in one tenant = %v; want ErrDuplicate", err)
	}
	// a version of A's scope, written as B, is refused
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.AddAgentScopeVersion(&store.AgentScopeVersion{ScopeID: a, Version: 9, Snapshot: "{}", Actor: "x", ChangedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a version naming another tenant's scope was accepted")
	}
	err = f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		s, err := c.AgentScopeByKey("bot")
		if err != nil || s.Status != store.AgentScopeActive || s.Version != 1 {
			t.Errorf("A's scope after B's refused writes = %+v, %v", s, err)
		}
		if vs, err := c.AgentScopeVersions(a); err != nil || len(vs) != 1 {
			t.Errorf("A's versions after B's refused write = %v, %v", vs, err)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func agentScopesCovered() map[string]bool {
	// TestIsolation_AgentScopes and TestIsolation_AgentScopeWrites
	return map[string]bool{"AgentScopes": true, "AgentScopeByKey": true, "InsertAgentScope": true, "SaveAgentScope": true,
		"AddAgentScopeVersion": true, "AgentScopeVersions": true}
}
