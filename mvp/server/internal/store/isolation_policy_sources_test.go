package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Per-tenant policy sources and their versions (schema/0917, issue #649): a
// tenant writes, lists and versions only its own sources; the same key in two
// tenants is two sources.

const invA = `@id("inv") @severity("high") forbid (principal, action == Tessera::Action::"exist", resource);`

func TestIsolation_PolicySources(t *testing.T) {
	f := storetest.TwoTenants(t)
	inA(t, f, func(c *store.TenantTx) error {
		s := &store.PolicySource{Kind: store.PolicyKindInvariant, Key: "inv", Cedar: invA, Status: store.PolicyActive, UpdatedBy: "a"}
		if changed, err := c.PutPolicySource(s, storetest.Now); err != nil || !changed || s.Version != 1 || len(s.SHA256) != 64 {
			t.Fatalf("A put = %v %v %+v", changed, err, s)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.PolicySource(store.PolicyKindInvariant, "inv"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's source: %v", err)
		}
		if ss, err := c.PolicySources(store.PolicyKindInvariant); err != nil || len(ss) != 0 {
			t.Errorf("B lists A's sources: %v %v", ss, err)
		}
		if vs, err := c.PolicyVersions(store.PolicyKindInvariant, "inv"); err != nil || len(vs) != 0 {
			t.Errorf("B lists A's versions: %v %v", vs, err)
		}
		// the same key in B is B's own source, at version 1, and leaves A's alone
		s := &store.PolicySource{Kind: store.PolicyKindInvariant, Key: "inv", Cedar: invA + "\n// b", Status: store.PolicyDisabled, UpdatedBy: "b"}
		if changed, err := c.PutPolicySource(s, storetest.Now); err != nil || !changed || s.Version != 1 {
			t.Errorf("B put = %v %v %+v", changed, err, s)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		s, err := c.PolicySource(store.PolicyKindInvariant, "inv")
		if err != nil || s.Cedar != invA || s.Status != store.PolicyActive || s.Version != 1 || s.UpdatedBy != "a" {
			t.Errorf("A's source after B's put = %+v %v", s, err)
		}
		if vs, err := c.PolicyVersions(store.PolicyKindInvariant, "inv"); err != nil || len(vs) != 1 {
			t.Errorf("A's versions after B's put = %v %v", vs, err)
		}
		return nil
	})
}

func TestPolicySources_Versions(t *testing.T) {
	f := storetest.TwoTenants(t)
	later := storetest.Now.Add(time.Hour)
	inA(t, f, func(c *store.TenantTx) error {
		put := func(cedar, status, ref string, at time.Time) (bool, *store.PolicySource) {
			s := &store.PolicySource{Kind: store.PolicyKindInvariant, Key: "inv", Cedar: cedar, Status: status, PolicyRef: ref, UpdatedBy: "a"}
			changed, err := c.PutPolicySource(s, at)
			if err != nil {
				t.Fatal(err)
			}
			return changed, s
		}
		if ch, s := put(invA, store.PolicyActive, "", storetest.Now); !ch || s.Version != 1 {
			t.Fatalf("first put = %v %+v", ch, s)
		}
		if ch, _ := put(invA, store.PolicyActive, "", later); ch {
			t.Error("an identical put changed the source")
		}
		if ch, s := put(invA, store.PolicyDisabled, "", later); !ch || s.Version != 2 {
			t.Errorf("disable = %v %+v", ch, s)
		}
		if ch, s := put(invA+"\n// 2", store.PolicyActive, `{"commit":"c1"}`, later); !ch || s.Version != 3 {
			t.Errorf("edit = %v %+v", ch, s)
		}
		vs, err := c.PolicyVersions(store.PolicyKindInvariant, "inv")
		if err != nil || len(vs) != 3 {
			t.Fatalf("versions = %v %v", vs, err)
		}
		for i, v := range vs {
			if v.Version != i+1 {
				t.Errorf("version %d at %d", v.Version, i)
			}
		}
		if vs[1].Status != store.PolicyDisabled || vs[2].PolicyRef != `{"commit":"c1"}` || !vs[0].At.Equal(storetest.Now) {
			t.Errorf("history = %+v %+v %+v", vs[0], vs[1], vs[2])
		}
		cur, err := c.PolicySource(store.PolicyKindInvariant, "inv")
		if err != nil || cur.Version != 3 || cur.SHA256 != vs[2].SHA256 || !strings.HasSuffix(cur.Cedar, "// 2") {
			t.Errorf("current = %+v %v", cur, err)
		}
		return nil
	})
	// the schema and the store bound what is stored
	for name, s := range map[string]*store.PolicySource{
		"empty":      {Kind: store.PolicyKindInvariant, Key: "x", Cedar: "", Status: store.PolicyActive, UpdatedBy: "a"},
		"oversize":   {Kind: store.PolicyKindInvariant, Key: "x", Cedar: strings.Repeat("x", store.MaxPolicySourceBytes+1), Status: store.PolicyActive, UpdatedBy: "a"},
		"bad kind":   {Kind: "role", Key: "x", Cedar: invA, Status: store.PolicyActive, UpdatedBy: "a"},
		"bad status": {Kind: store.PolicyKindInvariant, Key: "x", Cedar: invA, Status: "retired", UpdatedBy: "a"},
		"empty key":  {Kind: store.PolicyKindInvariant, Key: "", Cedar: invA, Status: store.PolicyActive, UpdatedBy: "a"},
		"long key":   {Kind: store.PolicyKindInvariant, Key: strings.Repeat("k", 65), Cedar: invA, Status: store.PolicyActive, UpdatedBy: "a"},
	} {
		err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
			_, err := c.PutPolicySource(s, later)
			return err
		})
		if err == nil {
			t.Errorf("%s source accepted", name)
		}
	}
}

func policySourcesCovered() map[string]bool {
	return map[string]bool{"PolicySource": true, "PolicySources": true, "PutPolicySource": true, "PolicyVersions": true} // the tests above
}
