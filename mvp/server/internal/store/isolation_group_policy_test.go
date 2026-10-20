package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Policy groups as code (issue #52, GR-9): a tenant's policy sources, compiled
// nodes and node uses are its own. Another tenant's group or node looks
// nonexistent, the same node hash can exist in two tenants, and a row naming
// another tenant's group is refused by the guard triggers.

type policyIDs struct {
	group, node store.GroupID
}

func seedPolicy(t *testing.T, f *storetest.Fixture) map[string]policyIDs {
	t.Helper()
	base := seedEngine(t, f)
	out := map[string]policyIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		ids := policyIDs{group: base[tn.Slug].g1, node: base[tn.Slug].g2}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			n := &store.GrpPolicyNode{Hash: "n-shared", Kind: store.NodeAttr, Attr: "campus", Value: "main", GroupID: ids.node, CreatedAt: storetest.Now}
			if err := c.InsertGrpPolicyNode(n); err != nil {
				return err
			}
			if err := c.SetGrpPolicySource(&store.GrpPolicySource{GroupID: ids.group, Origin: store.PolicyOriginRepo, Path: "groups/a.cedar",
				CommitSHA: "c1", Cedar: "x", CedarSHA256: "h", AllowNode: "n-shared", CompiledSHA256: "k", AppliedAt: storetest.Now}); err != nil {
				return err
			}
			return c.ReplaceGrpPolicyUses(ids.group, []string{"n-shared"})
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_GroupPolicyTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedPolicy(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	notFound := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want ErrNotFound", what, err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		_, err := c.GrpPolicySource(a.group)
		notFound("GrpPolicySource(A's group)", err)
		if s, err := c.GrpPolicySource(b.group); err != nil || s.Path != "groups/a.cedar" || s.AllowNode != "n-shared" {
			t.Errorf("GrpPolicySource(B's) = %+v, %v", s, err)
		}
		if ss, err := c.GrpPolicySources(""); err != nil || len(ss) != 1 || ss[0].GroupID != b.group {
			t.Errorf("GrpPolicySources = %v, %v; want only B's", ss, err)
		}
		if n, err := c.GrpPolicyNode("n-shared"); err != nil || n.GroupID != b.node {
			t.Errorf("GrpPolicyNode in B = %+v, %v; want B's group", n, err)
		}
		_, err = c.GrpPolicyNodeOfGroup(a.node)
		notFound("GrpPolicyNodeOfGroup(A's)", err)
		if s, err := c.GrpPolicySourceByPath("groups/a.cedar"); err != nil || s.GroupID != b.group {
			t.Errorf("GrpPolicySourceByPath in B = %+v, %v; want B's group", s, err)
		}
		if ns, err := c.GrpPolicyNodes(store.NodeAttr); err != nil || len(ns) != 1 || ns[0].GroupID != b.node {
			t.Errorf("GrpPolicyNodes = %v, %v; want only B's", ns, err)
		}
		if hs, err := c.GrpPolicyUsesOf(a.group); err != nil || len(hs) != 0 {
			t.Errorf("GrpPolicyUsesOf(A's group) = %v, %v", hs, err)
		}
		if n, err := c.GrpPolicyUsers("n-shared"); err != nil || n != 1 {
			t.Errorf("GrpPolicyUsers = %d, %v; want B's one", n, err)
		}
		notFound("DeleteGrpPolicySource(A's)", c.DeleteGrpPolicySource(a.group))
		notFound("SetGrpGroupPolicy(A's)", c.SetGrpGroupPolicy(a.group, store.ManagedByPolicyRepo, "{}"))
		return nil
	})
	// B deleting its own node and source leaves A's alone
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.ReplaceGrpPolicyUses(b.group, nil); err != nil {
			return err
		}
		if un, err := c.GrpPolicyNodesUnused(); err != nil || len(un) != 1 {
			t.Errorf("GrpPolicyNodesUnused = %v, %v", un, err)
		}
		if err := c.DeleteGrpPolicyNode("n-shared"); err != nil {
			return err
		}
		return c.DeleteGrpPolicySource(b.group)
	})
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if _, err := c.GrpPolicyNode("n-shared"); err != nil {
			t.Errorf("A's node: %v", err)
		}
		if _, err := c.GrpPolicySource(a.group); err != nil {
			t.Errorf("A's source: %v", err)
		}
		if hs, err := c.GrpPolicyUsesOf(a.group); err != nil || len(hs) != 1 {
			t.Errorf("A's uses = %v, %v", hs, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// a node hash is unique within a tenant, and so is a group's node
	inB(t, f, func(c *store.TenantTx) error {
		n := &store.GrpPolicyNode{Hash: "n-two", Kind: store.NodeEmpty, GroupID: b.node, CreatedAt: storetest.Now}
		if err := c.InsertGrpPolicyNode(n); err != nil {
			t.Errorf("a node: %v", err)
		}
		if err := c.InsertGrpPolicyNode(&store.GrpPolicyNode{Hash: "n-two", Kind: store.NodeEmpty, GroupID: b.group, CreatedAt: storetest.Now}); err == nil {
			t.Error("a node hash was used twice in one tenant")
		}
		return nil
	})
}

// groupPolicyCovered lists the repository methods of GR-9 that the isolation
// tests here exercise.
func groupPolicyCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{"SetGrpPolicySource", "GrpPolicySource", "GrpPolicySourceByPath", "GrpPolicySources",
		"DeleteGrpPolicySource", "SetGrpGroupPolicy", "InsertGrpPolicyNode", "GrpPolicyNode", "GrpPolicyNodeOfGroup", "GrpPolicyNodes",
		"GrpPolicyNodesUnused", "DeleteGrpPolicyNode", "ReplaceGrpPolicyUses", "GrpPolicyUsesOf", "GrpPolicyUsers"} {
		m[name] = true
	}
	return m
}

func TestIsolation_GroupPolicyCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedPolicy(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"source of A's group": func(c *store.TenantTx) error {
			return c.SetGrpPolicySource(&store.GrpPolicySource{GroupID: a.node, Origin: store.PolicyOriginUI, Cedar: "x", CedarSHA256: "h",
				CompiledSHA256: "k", AppliedAt: storetest.Now})
		},
		"source stamped with A": func(c *store.TenantTx) error {
			return c.SetGrpPolicySource(&store.GrpPolicySource{TenantID: f.A.ID, GroupID: b.node, Origin: store.PolicyOriginUI, Cedar: "x",
				CedarSHA256: "h", CompiledSHA256: "k", AppliedAt: storetest.Now})
		},
		"node on A's group": func(c *store.TenantTx) error {
			return c.InsertGrpPolicyNode(&store.GrpPolicyNode{Hash: "x", Kind: store.NodeEmpty, GroupID: a.node, CreatedAt: storetest.Now})
		},
		"node stamped with A": func(c *store.TenantTx) error {
			return c.InsertGrpPolicyNode(&store.GrpPolicyNode{TenantID: f.A.ID, Hash: "x", Kind: store.NodeEmpty, GroupID: b.node, CreatedAt: storetest.Now})
		},
		"use by A's group": func(c *store.TenantTx) error { return c.ReplaceGrpPolicyUses(a.group, []string{"n-shared"}) },
		"use of a node B lacks": func(c *store.TenantTx) error {
			return c.ReplaceGrpPolicyUses(b.group, []string{"n-only-in-a"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "use of a node B lacks" {
				// the node exists in A only
				if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
					return c.InsertGrpPolicyNode(&store.GrpPolicyNode{Hash: "n-only-in-a", Kind: store.NodeEmpty, GroupID: a.group, CreatedAt: storetest.Now})
				}); err != nil {
					t.Fatal(err)
				}
			}
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
}
