package nhi_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/nhi"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

func inventory(t *testing.T, f *storetest.Fixture, tenant storetest.Tenant) map[string]nhi.Item {
	t.Helper()
	out := map[string]nhi.Item{}
	err := f.DB.ReadTenant(context.Background(), tenant.ID, func(c *store.TenantTx) error {
		g, err := graph.Build(c, storetest.Now)
		if err != nil {
			return err
		}
		u, err := usage.Build(c, storetest.Now)
		if err != nil {
			return err
		}
		items, err := nhi.Inventory(c, g, u)
		for _, it := range items {
			out[it.Name[:min(len(it.Name), 7)]] = it
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func trustResidual(flags ...string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"text": "x", "flags": flags})
	return b
}

// The trust risks the evaluator finds in a role show on the NHI that holds the
// role's account (design §11.4), from the newest snapshot of the tenant only.
func TestInventoryShowsAWSTrustFlags(t *testing.T) {
	f := storetest.TwoTenants(t)
	// svc-etl's AWS account is the one named "svc-etl"; its role ARN, for the test
	const role = "svc-etl"

	before := inventory(t, f, f.A)["svc-etl"]
	if slices.Contains(before.Flags, "wildcard_oidc_trust") {
		t.Fatalf("flags before any snapshot = %v", before.Flags)
	}

	add := func(tenant storetest.Tenant, snap string, taken int, edges ...*store.AWSTrustEdge) {
		err := f.DB.InTenant(context.Background(), tenant.ID, func(c *store.TenantTx) error {
			if _, err := c.PutAWSSnapshot(&store.AWSSnapshot{ID: snap, TakenAt: storetest.Now.Add(time.Duration(taken) * time.Hour),
				CatalogVersion: "v", Source: store.AWSSourceConnector}); err != nil {
				return err
			}
			for _, e := range edges {
				e.SnapshotID = snap
				if err := c.AddAWSTrustEdge(e); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	edge := func(mech string, flags ...string) *store.AWSTrustEdge {
		return &store.AWSTrustEdge{FromARN: "from", ToRoleARN: role, Mechanism: mech, Outcome: "conditional", Residual: trustResidual(flags...)}
	}
	add(f.A, "old", -1, edge("assume_role", "missing_external_id"))
	add(f.A, "new", 0, edge("assume_role_with_web_identity", "wildcard_oidc_trust"), edge("assume_role", "public_trust", "made_up_flag"),
		edge("assume_role"))

	a := inventory(t, f, f.A)["svc-etl"]
	for _, want := range []string{"wildcard_oidc_trust", "public_trust"} {
		if !slices.Contains(a.Flags, want) {
			t.Errorf("flags = %v, want %s", a.Flags, want)
		}
	}
	for _, not := range []string{"missing_external_id", "made_up_flag"} {
		if slices.Contains(a.Flags, not) {
			t.Errorf("flags = %v hold %s (an older snapshot, or an unknown flag)", a.Flags, not)
		}
	}
	if a.Risk <= before.Risk {
		t.Errorf("risk %d did not rise from %d", a.Risk, before.Risk)
	}
	if n := countFlag(a.Flags, "public_trust"); n != 1 {
		t.Errorf("public_trust shown %d times", n)
	}

	// tenant B has the same account and no snapshot: nothing of A's shows
	b := inventory(t, f, f.B)["svc-etl"]
	if slices.Contains(b.Flags, "wildcard_oidc_trust") || slices.Contains(b.Flags, "public_trust") {
		t.Errorf("tenant B shows A's trust flags: %v", b.Flags)
	}
	flags, err := trustFlags(f, f.B)
	if err != nil || len(flags) != 0 {
		t.Errorf("TrustFlags(B) = %v, %v", flags, err)
	}
	flags, err = trustFlags(f, f.A)
	if err != nil || !slices.Equal(flags[role], []string{"public_trust", "wildcard_oidc_trust"}) {
		t.Errorf("TrustFlags(A) = %v, %v", flags, err)
	}
}

func trustFlags(f *storetest.Fixture, tenant storetest.Tenant) (map[string][]string, error) {
	var out map[string][]string
	err := f.DB.ReadTenant(context.Background(), tenant.ID, func(c *store.TenantTx) (err error) {
		out, err = nhi.TrustFlags(c)
		return err
	})
	return out, err
}

func countFlag(flags []string, f string) int {
	n := 0
	for _, x := range flags {
		if x == f {
			n++
		}
	}
	return n
}
