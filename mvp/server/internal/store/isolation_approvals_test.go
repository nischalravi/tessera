package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Approval routing isolation (issue #165): a tenant sees and changes only its
// own policies, stages and delegations.

type apprRows struct {
	reqRows
	other *store.PlatformUser
	deleg string
}

func seedApprRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) apprRows {
	t.Helper()
	r := apprRows{reqRows: seedReqRows(t, db, tn, tag), deleg: "deleg-" + tag}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.other = &store.PlatformUser{DisplayName: "delegate " + tag, IdentityID: &r.alice, CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(r.other); err != nil {
			return err
		}
		if err := c.PutApprovalPolicy(&store.ApprovalPolicy{CatalogItemID: r.item, Stages: []string{"manager", "decider"},
			EscalateAfterHours: 24, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		start := storetest.Now
		if err := c.InsertRequestStage(&store.RequestStage{LineID: r.line, Idx: 0, Kind: "manager", AssigneeID: &r.alice,
			Status: store.StageWaiting, StartedAt: &start}); err != nil {
			return err
		}
		return c.InsertApprovalDelegation(&store.ApprovalDelegationRow{ID: r.deleg, FromUser: r.user.ID.String(), ToUser: r.other.ID.String(),
			StartsAt: storetest.Now.Add(-time.Hour), EndsAt: storetest.Now.Add(time.Hour), Reason: "leave", CreatedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func apprFixture(t *testing.T) (*storetest.Fixture, apprRows, apprRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedApprRows(t, f.DB, f.A, "a"), seedApprRows(t, f.DB, f.B, "b")
}

func TestIsolation_ApprovalReads(t *testing.T) {
	f, a, b := apprFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if ps, err := c.ApprovalPolicies(); err != nil || len(ps) != 1 || ps[0].CatalogItemID != b.item {
			t.Errorf("ApprovalPolicies = %v, %v", ps, err)
		}
		if _, err := c.ApprovalPolicy(a.item); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ApprovalPolicy(A's) = %v", err)
		}
		if ss, err := c.RequestStages(a.line); err != nil || len(ss) != 0 {
			t.Errorf("RequestStages(A's) = %v, %v", ss, err)
		}
		if ws, err := c.WaitingStages(); err != nil || len(ws) != 1 || ws[0].LineID != b.line {
			t.Errorf("WaitingStages = %v, %v", ws, err)
		}
		if us, err := c.UsersLinkedTo(a.alice); err != nil || len(us) != 0 {
			t.Errorf("UsersLinkedTo(A's alice) = %v, %v", us, err)
		}
		if ds, err := c.ApprovalDelegations(""); err != nil || len(ds) != 1 || ds[0].ID != b.deleg {
			t.Errorf("ApprovalDelegations = %v, %v", ds, err)
		}
		if _, err := c.ApprovalDelegation(a.deleg); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ApprovalDelegation(A's) = %v", err)
		}
		if ds, err := c.ActiveApprovalDelegationsTo(a.other.ID.String(), storetest.Now); err != nil || len(ds) != 0 {
			t.Errorf("ActiveApprovalDelegationsTo(A's user) = %v, %v", ds, err)
		}
		return nil
	})
}

var apprMutations = map[string]func(c *store.TenantTx, a, b apprRows) error{
	"PutApprovalPolicy": func(c *store.TenantTx, a, _ apprRows) error {
		return c.PutApprovalPolicy(&store.ApprovalPolicy{CatalogItemID: a.item, Stages: []string{"decider"}, EscalateAfterHours: 1, UpdatedAt: storetest.Now})
	},
	"InsertRequestStage": func(c *store.TenantTx, a, _ apprRows) error {
		return c.InsertRequestStage(&store.RequestStage{LineID: a.line, Idx: 1, Kind: "decider", Status: store.StageQueued})
	},
	"SaveRequestStage": func(c *store.TenantTx, a, _ apprRows) error {
		return c.SaveRequestStage(&store.RequestStage{LineID: a.line, Idx: 0, Status: store.StageApproved}, store.StageWaiting)
	},
	"CloseOpenStages": func(c *store.TenantTx, a, _ apprRows) error {
		if err := c.CloseOpenStages(a.line); err != nil {
			return err
		}
		return store.ErrNotFound // nothing in B to close; A's dump proves its stage stayed
	},
	"InsertApprovalDelegation": func(c *store.TenantTx, a, b apprRows) error {
		return c.InsertApprovalDelegation(&store.ApprovalDelegationRow{ID: "x", FromUser: b.user.ID.String(), ToUser: a.other.ID.String(),
			StartsAt: storetest.Now, EndsAt: storetest.Now.Add(time.Hour), Reason: "x", CreatedAt: storetest.Now})
	},
	"RevokeApprovalDelegation": func(c *store.TenantTx, a, b apprRows) error {
		return c.RevokeApprovalDelegation(a.deleg, b.user.ID.String(), storetest.Now)
	},
}

func TestIsolation_ApprovalMutationsScoped(t *testing.T) {
	for name, fn := range apprMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := apprFixture(t)
			before := apprDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v", name, err)
			}
			if apprDump(t, f.DB, f.A.ID) != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func apprDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := reqDump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		ps, err := c.ApprovalPolicies()
		if err != nil {
			return err
		}
		ws, err := c.WaitingStages()
		if err != nil {
			return err
		}
		lines, err := c.RequestLines(store.RequestFilter{})
		if err != nil {
			return err
		}
		var all []*store.RequestStage
		for _, l := range lines {
			ss, err := c.RequestStages(l.ID)
			if err != nil {
				return err
			}
			all = append(all, ss...)
		}
		ds, err := c.ApprovalDelegations("")
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{ps, ws, all, ds})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func approvalsCovered() map[string]bool {
	out := map[string]bool{}
	for k := range apprMutations {
		out[k] = true
	}
	for _, k := range []string{"ApprovalPolicies", "ApprovalPolicy", "RequestStages", "WaitingStages", "UsersLinkedTo",
		"ApprovalDelegations", "ApprovalDelegation", "ActiveApprovalDelegationsTo"} {
		out[k] = true // TestIsolation_ApprovalReads
	}
	return out
}
