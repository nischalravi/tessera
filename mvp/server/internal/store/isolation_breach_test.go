package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Vendor breach response (issue #475): a tenant sees and changes only its own
// plans and items; an item cannot point at another tenant's plan, nor a plan at
// another tenant's rotation run.

func seedBreachPlan(t *testing.T, f *storetest.Fixture, tn storetest.Tenant) (planID, itemID string) {
	t.Helper()
	err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		p := &store.BreachPlan{Vendor: "acme", Reason: "vendor breach of " + tn.Slug, CreatedBy: "admin", CreatedAt: storetest.Now}
		if err := c.InsertBreachPlan(p); err != nil {
			return err
		}
		planID = p.ID
		if err := c.AddBreachItem(p.ID, &store.BreachItem{Kind: store.BreachKindSecret, Ref: "1", Label: "key", Action: store.BreachActionRotate}, storetest.Now); err != nil {
			return err
		}
		its, err := c.BreachItems(p.ID)
		if err != nil || len(its) != 1 {
			t.Fatalf("items = %v, %v", its, err)
		}
		itemID = its[0].ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return planID, itemID
}

func TestIsolation_BreachPlansAndItems(t *testing.T) {
	f := storetest.TwoTenants(t)
	aPlan, aItem := seedBreachPlan(t, f, f.A)
	bPlan, _ := seedBreachPlan(t, f, f.B)
	inB(t, f, func(c *store.TenantTx) error {
		ps, err := c.BreachPlans()
		if err != nil || len(ps) != 1 || ps[0].ID != bPlan {
			t.Errorf("BreachPlans = %v, %v", ps, err)
		}
		if _, err := c.BreachPlan(aPlan); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BreachPlan(A's) = %v, want ErrNotFound", err)
		}
		if its, err := c.BreachItems(aPlan); err != nil || len(its) != 0 {
			t.Errorf("BreachItems(A's plan) = %v, %v", its, err)
		}
		if _, err := c.BreachItem(aPlan, aItem); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BreachItem(A's) = %v, want ErrNotFound", err)
		}
		// changes aimed at A's rows touch nothing
		if err := c.StartBreachPlan(aPlan, nil, "b-admin", storetest.Now); err != nil {
			return err
		}
		if err := c.CompleteBreachPlan(aPlan, "{}", storetest.Now); err != nil {
			return err
		}
		if err := c.SetBreachItemState(aItem, store.BreachVerified, "x", nil, nil, storetest.Now); err != nil {
			return err
		}
		return c.AttestBreachItem(aItem, "b-admin", "not mine to attest", storetest.Now)
	})
	inA(t, f, func(c *store.TenantTx) error {
		p, err := c.BreachPlan(aPlan)
		if err != nil || p.Status != store.BreachPlanned || p.StartedBy != nil || p.CompletedAt != nil {
			t.Errorf("A's plan after B's writes = %+v, %v", p, err)
		}
		it, err := c.BreachItem(aPlan, aItem)
		if err != nil || it.State != store.BreachPending || it.AttestedBy != nil {
			t.Errorf("A's item after B's writes = %+v, %v", it, err)
		}
		return nil
	})
}

func TestIsolation_BreachCrossTenantReference(t *testing.T) {
	f := storetest.TwoTenants(t)
	aPlan, _ := seedBreachPlan(t, f, f.A)
	// B cannot add an item to A's plan
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.AddBreachItem(aPlan, &store.BreachItem{Kind: store.BreachKindSecret, Ref: "9", Label: "x", Action: store.BreachActionRotate}, storetest.Now)
	})
	if err == nil {
		t.Fatal("an item was added to another tenant's plan")
	}
	// nor link its plan to A's rotation run
	bulkA := f.A.Refs["rot:bulk"]
	bPlan, _ := seedBreachPlan(t, f, f.B)
	err = f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.StartBreachPlan(bPlan, &bulkA, "b-admin", storetest.Now)
	})
	if err == nil {
		t.Fatal("a plan was linked to another tenant's rotation run")
	}
}

// The state machine: an attested item is final for a re-read, a verified item
// is final for an attestation, a completed plan is final.
func TestBreachItemAndPlanStatesAreFinal(t *testing.T) {
	f := storetest.TwoTenants(t)
	planID, itemID := seedBreachPlan(t, f, f.A)
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.AttestBreachItem(itemID, "alice", "rotated by hand in the console", storetest.Now); err != nil {
			return err
		}
		if err := c.SetBreachItemState(itemID, store.BreachPending, "re-read", nil, nil, storetest.Now); err != nil {
			return err
		}
		it, err := c.BreachItem(planID, itemID)
		if err != nil || it.State != store.BreachAttested || it.AttestedBy == nil || *it.AttestedBy != "alice" {
			t.Errorf("attested item = %+v, %v", it, err)
		}
		if err := c.StartBreachPlan(planID, nil, "alice", storetest.Now); err != nil {
			return err
		}
		if err := c.CompleteBreachPlan(planID, `{"complete":true}`, storetest.Now); err != nil {
			return err
		}
		if err := c.StartBreachPlan(planID, nil, "mallory", storetest.Now); err != nil {
			return err
		}
		p, err := c.BreachPlan(planID)
		if err != nil || p.Status != store.BreachCompleted || p.Report == nil || *p.StartedBy != "alice" {
			t.Errorf("completed plan = %+v, %v", p, err)
		}
		// the same credential is added to a plan once
		if err := c.AddBreachItem(planID, &store.BreachItem{Kind: store.BreachKindSecret, Ref: "1", Label: "key", Action: store.BreachActionRotate}, storetest.Now); err != nil {
			return err
		}
		if its, err := c.BreachItems(planID); err != nil || len(its) != 1 {
			t.Errorf("items after a duplicate add = %v, %v", its, err)
		}
		return nil
	})
}

func breachCovered() map[string]bool {
	return map[string]bool{"InsertBreachPlan": true, "BreachPlans": true, "BreachPlan": true, "StartBreachPlan": true, "CompleteBreachPlan": true,
		"AddBreachItem": true, "BreachItems": true, "BreachItem": true, "SetBreachItemState": true, "AttestBreachItem": true} // the tests above
}
