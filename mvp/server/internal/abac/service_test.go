package abac_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/abac"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func cond(t *testing.T, s string) *abac.Node {
	t.Helper()
	n, err := abac.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func refusal(err error) string {
	var r *abac.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

// Create, Update and Retire version the policy, audit each change in the same
// transaction, and refuse stale versions, duplicate names and policies in use.
func TestService_VersioningAndAudit(t *testing.T) {
	f := storetest.TwoTenants(t)
	by := abac.Actor{UserID: uuid.New(), Display: "Pat"}
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		p, err := abac.Create(c, abac.Spec{Name: " Finance ", Condition: cond(t, `{"attr":"identity.department","op":"eq","value":"Finance"}`), Note: "first"}, by, storetest.Now)
		if err != nil || p.Version != 1 || p.Name != "Finance" {
			t.Fatalf("Create = %+v, %v", p, err)
		}
		if _, err := abac.Create(c, abac.Spec{Name: "Finance", Condition: p2(t)}, by, storetest.Now); refusal(err) != "name_taken" {
			t.Errorf("duplicate name = %v", err)
		}
		for name, s := range map[string]abac.Spec{
			"no name":      {Condition: p2(t)},
			"no condition": {Name: "x"},
			"long note":    {Name: "x", Condition: p2(t), Note: string(make([]byte, abac.MaxNote+1))},
		} {
			if _, err := abac.Create(c, s, by, storetest.Now); refusal(err) == "" {
				t.Errorf("%s accepted", name)
			}
		}
		if _, err := abac.Update(c, p.ID, 4, abac.Spec{Name: "Finance", Condition: p2(t)}, by, storetest.Now); refusal(err) != "version_conflict" {
			t.Errorf("stale update = %v", err)
		}
		u, err := abac.Update(c, p.ID, 1, abac.Spec{Name: "Finance", Condition: p2(t), Note: "widen"}, by, storetest.Now)
		if err != nil || u.Version != 2 {
			t.Fatalf("Update = %+v, %v", u, err)
		}
		vs, err := c.AbacPolicyVersions(p.ID)
		if err != nil || len(vs) != 2 || vs[0].Version != 2 || *vs[0].Note != "widen" || *vs[1].Note != "first" {
			t.Errorf("versions = %+v, %v", vs, err)
		}
		// a binding makes it in use; retire needs it free and a reason
		if err := abac.Bind(c, store.BindCatalogItem, "item-x", p.ID, by, storetest.Now); err == nil {
			// catalog item missing: the guard only checks other tenants, so this binds
			if _, err := abac.Retire(c, p.ID, "done", by, storetest.Now); refusal(err) != "policy_in_use" {
				t.Errorf("retire in use = %v", err)
			}
			if err := abac.Bind(c, store.BindCatalogItem, "item-x", "", by, storetest.Now); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Fatal(err)
		}
		if _, err := abac.Retire(c, p.ID, " ", by, storetest.Now); refusal(err) != "invalid_reason" {
			t.Errorf("retire without a reason = %v", err)
		}
		r, err := abac.Retire(c, p.ID, "done", by, storetest.Now)
		if err != nil || r.Status != store.AbacRetired || r.Version != 3 {
			t.Fatalf("Retire = %+v, %v", r, err)
		}
		if _, err := abac.Update(c, p.ID, 3, abac.Spec{Name: "Finance", Condition: p2(t)}, by, storetest.Now); refusal(err) != "policy_retired" {
			t.Errorf("update retired = %v", err)
		}
		if err := abac.Bind(c, store.BindCatalogItem, "item-y", p.ID, by, storetest.Now); refusal(err) != "policy_retired" {
			t.Errorf("bind retired = %v", err)
		}
		if act, _ := abac.Active(c); len(act) != 0 {
			t.Errorf("Active lists a retired policy: %v", act)
		}
		evs, err := c.AuditEvents(store.AuditFilter{})
		if err != nil {
			return err
		}
		got := map[string]int{}
		for _, e := range evs {
			got[e.Action]++
		}
		for a, n := range map[string]int{"abac.policy.create": 1, "abac.policy.update": 1, "abac.policy.retire": 1,
			"abac.binding.put": 1, "abac.binding.remove": 1} {
			if got[a] != n {
				t.Errorf("audit %s = %d, want %d", a, got[a], n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func p2(t *testing.T) *abac.Node {
	return cond(t, `{"any":[{"attr":"identity.department","op":"eq","value":"Finance"},{"attr":"identity.type","op":"eq","value":"service"}]}`)
}

// Simulate reports who gains and who loses against the saved version, counts
// identities a missing attribute denied, and writes nothing.
func TestSimulate(t *testing.T) {
	f := storetest.TwoTenants(t)
	by := abac.Actor{UserID: uuid.New(), Display: "Pat"}
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		people, err := c.Identities()
		if err != nil {
			return err
		}
		types := map[string]int{}
		for _, p := range people {
			types[p.Type]++
		}
		if types["human"] == 0 || types["service"] == 0 {
			t.Fatalf("fixture has no mix of identity types: %v", types)
		}
		saved, err := abac.Create(c, abac.Spec{Name: "Humans", Condition: cond(t, `{"attr":"identity.type","op":"eq","value":"human"}`)}, by, storetest.Now)
		if err != nil {
			return err
		}
		// draft: services instead of humans -> every human loses, every service gains
		draft := cond(t, `{"attr":"identity.type","op":"eq","value":"service"}`)
		res, err := abac.Simulate(c, draft, saved, nil, storetest.Now)
		if err != nil {
			return err
		}
		if res.Evaluated != len(people) || res.Before != types["human"] || res.Matching != types["service"] ||
			res.LoseCount != types["human"] || res.GainCount != types["service"] || res.Unchanged != len(people)-types["human"]-types["service"] ||
			res.CurrentVer != 1 {
			t.Errorf("Simulate = %+v (types %v)", res, types)
		}
		for _, p := range res.Gains {
			if p.Type != "service" {
				t.Errorf("gain %+v is not a service", p)
			}
		}
		for _, p := range res.Loses {
			if p.Type != "human" {
				t.Errorf("loss %+v is not a human", p)
			}
		}
		// a new policy (no saved version) only gains
		res, err = abac.Simulate(c, draft, nil, nil, storetest.Now)
		if err != nil || res.LoseCount != 0 || res.GainCount != types["service"] || res.Before != 0 || res.CurrentVer != 0 {
			t.Errorf("Simulate without a saved version = %+v, %v", res, err)
		}
		// an attribute no identity has: nobody matches and every identity is counted as denied for it
		res, err = abac.Simulate(c, cond(t, `{"attr":"identity.clearance","op":"eq","value":"s"}`), saved, nil, storetest.Now)
		if err != nil || res.Matching != 0 || res.NoAttrs != len(people) || res.LoseCount != types["human"] {
			t.Errorf("Simulate on a missing attribute = %+v, %v", res, err)
		}
		// resource and context attributes shared by every evaluation
		res, err = abac.Simulate(c, cond(t, `{"all":[{"attr":"resource.risk","op":"eq","value":"high"},{"attr":"context.aal","op":"gte","value":2}]}`), nil,
			abac.Attrs{"resource.risk": "high", "context.aal": 2.0}, storetest.Now)
		if err != nil || res.Matching != len(people) {
			t.Errorf("Simulate with context = %+v, %v", res, err)
		}
		res, _ = abac.Simulate(c, cond(t, `{"attr":"context.aal","op":"gte","value":2}`), nil, nil, storetest.Now)
		if res.Matching != 0 {
			t.Errorf("a missing context.aal matched %d identities", res.Matching)
		}
		if _, err := abac.Simulate(c, &abac.Node{}, nil, nil, storetest.Now); err == nil {
			t.Error("an invalid draft was simulated")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
