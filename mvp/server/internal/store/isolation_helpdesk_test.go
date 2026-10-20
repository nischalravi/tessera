package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Verified help-desk resets (issue #108): a tenant sees and changes only its
// own cases, verifications, signals and findings; a row naming another
// tenant's identity, case or platform user is refused by the guard triggers.

type helpdeskSeed struct {
	caseID  map[string]string // by tenant slug
	user    map[string]uuid.UUID
	finding map[string]string
}

func seedHelpdesk(t *testing.T, f *storetest.Fixture) helpdeskSeed {
	t.Helper()
	s := helpdeskSeed{caseID: map[string]string{}, user: map[string]uuid.UUID{}, finding: map[string]string{}}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			u := &store.PlatformUser{TenantID: tn.ID, DisplayName: "agent-" + tn.Slug}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			s.user[tn.Slug] = u.ID
			hc := &store.HelpdeskCase{IdentityID: tn.IDs["alice"], Kind: "mfa", System: "okta", Reason: "lost phone",
				RequestedBy: "agent", RequestedByUserID: &u.ID}
			if err := c.InsertHelpdeskCase(hc, storetest.Now); err != nil {
				return err
			}
			s.caseID[tn.Slug] = hc.ID
			if err := c.InsertHelpdeskVerification(&store.HelpdeskVerification{CaseID: hc.ID, Method: "callback",
				Outcome: "passed", VerifiedBy: "agent", VerifiedByUserID: &u.ID, Evidence: "called the HR number"}, storetest.Now); err != nil {
				return err
			}
			if err := c.InsertHelpdeskSignal(&store.HelpdeskSignal{IdentityID: tn.IDs["alice"], Kind: "sign_in",
				Location: "Oslo", OccurredAt: storetest.Now}, storetest.Now); err != nil {
				return err
			}
			fd := &store.HelpdeskFinding{CaseID: hc.ID, IdentityID: tn.IDs["alice"], Rule: "r", Detail: "{}"}
			if _, err := c.InsertHelpdeskFinding(fd, storetest.Now); err != nil {
				return err
			}
			s.finding[tn.Slug] = fd.ID
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestIsolation_HelpdeskReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	s := seedHelpdesk(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		cs, err := c.HelpdeskCases()
		if err != nil || len(cs) != 1 || cs[0].ID != s.caseID[f.B.Slug] {
			t.Errorf("HelpdeskCases = %v, %v", cs, err)
		}
		if _, err := c.HelpdeskCase(s.caseID[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("HelpdeskCase(A's) = %v", err)
		}
		if vs, err := c.HelpdeskVerifications(s.caseID[f.A.Slug]); err != nil || len(vs) != 0 {
			t.Errorf("HelpdeskVerifications(A's case) = %v, %v", vs, err)
		}
		if vs, err := c.HelpdeskVerifications(s.caseID[f.B.Slug]); err != nil || len(vs) != 1 {
			t.Errorf("HelpdeskVerifications(B's case) = %v, %v", vs, err)
		}
		if gs, err := c.HelpdeskSignals(f.A.IDs["alice"]); err != nil || len(gs) != 0 {
			t.Errorf("HelpdeskSignals(A's identity) = %v, %v", gs, err)
		}
		if gs, err := c.HelpdeskSignals(f.B.IDs["alice"]); err != nil || len(gs) != 1 {
			t.Errorf("HelpdeskSignals(B's identity) = %v, %v", gs, err)
		}
		fs, err := c.HelpdeskFindings()
		if err != nil || len(fs) != 1 || fs[0].ID != s.finding[f.B.Slug] {
			t.Errorf("HelpdeskFindings = %v, %v", fs, err)
		}
		if fs, err := c.HelpdeskFindingsForCase(s.caseID[f.A.Slug]); err != nil || len(fs) != 0 {
			t.Errorf("HelpdeskFindingsForCase(A's) = %v, %v", fs, err)
		}
		if cs, err := c.HelpdeskCasesExecutedSince(f.A.IDs["alice"], time.Time{}); err != nil || len(cs) != 0 {
			t.Errorf("HelpdeskCasesExecutedSince(A's identity) = %v, %v", cs, err)
		}
		if ids, err := c.PlatformUserIDsForIdentity(f.A.IDs["alice"]); err != nil || len(ids) != 0 {
			t.Errorf("PlatformUserIDsForIdentity(A's) = %v, %v", ids, err)
		}
		if admin, err := c.IdentityHoldsAdminRole(f.A.IDs["alice"], storetest.Now); err != nil || admin {
			t.Errorf("IdentityHoldsAdminRole(A's) = %v, %v", admin, err)
		}
		return nil
	})
}

func TestIsolation_HelpdeskWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	s := seedHelpdesk(t, f)
	aCase := s.caseID[f.A.Slug]
	// B cannot change, claim, approve or cancel A's case: it looks nonexistent
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"claim":  func(c *store.TenantTx) error { return c.ClaimHelpdeskCase(aCase, "b", storetest.Now) },
		"cancel": func(c *store.TenantTx) error { return c.CancelHelpdeskCase(aCase, storetest.Now) },
		"approve": func(c *store.TenantTx) error {
			return c.SetHelpdeskSecondApproval(aCase, store.UserRef{ID: s.user[f.B.Slug], Display: "b"}, storetest.Now)
		},
		"finish": func(c *store.TenantTx) error {
			return c.FinishHelpdeskCase(aCase, "executed", storetest.Now, "[]", "")
		},
	} {
		err := f.DB.InTenant(context.Background(), f.B.ID, fn)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s of A's case in B = %v, want ErrNotFound", name, err)
		}
	}
	// B names A's identity, case or platform user: the guard triggers refuse it
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"case for A's identity": func(c *store.TenantTx) error {
			return c.InsertHelpdeskCase(&store.HelpdeskCase{IdentityID: f.A.IDs["alice"], Kind: "mfa", System: "okta",
				Reason: "x", RequestedBy: "b"}, storetest.Now)
		},
		"case by A's user": func(c *store.TenantTx) error {
			u := s.user[f.A.Slug]
			return c.InsertHelpdeskCase(&store.HelpdeskCase{IdentityID: f.B.IDs["alice"], Kind: "mfa", System: "okta",
				Reason: "x", RequestedBy: "b", RequestedByUserID: &u}, storetest.Now)
		},
		"verification on A's case": func(c *store.TenantTx) error {
			return c.InsertHelpdeskVerification(&store.HelpdeskVerification{CaseID: aCase, Method: "callback",
				Outcome: "passed", VerifiedBy: "b"}, storetest.Now)
		},
		"signal for A's identity": func(c *store.TenantTx) error {
			return c.InsertHelpdeskSignal(&store.HelpdeskSignal{IdentityID: f.A.IDs["alice"], Kind: "sign_in",
				Location: "x", OccurredAt: storetest.Now}, storetest.Now)
		},
		"finding on A's case": func(c *store.TenantTx) error {
			_, err := c.InsertHelpdeskFinding(&store.HelpdeskFinding{CaseID: aCase, IdentityID: f.B.IDs["alice"], Rule: "other",
				Detail: "{}"}, storetest.Now)
			return err
		},
	} {
		err := f.DB.InTenant(context.Background(), f.B.ID, fn)
		if !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("%s = %v, want ErrCrossTenant", name, err)
		}
	}
	// A's case is untouched
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		hc, err := c.HelpdeskCase(aCase)
		if err != nil || hc.Status != store.HelpdeskOpen || hc.SecondApprover != nil {
			t.Errorf("A's case = %+v, %v", hc, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The claim is single-flight: a second claim of a claimed case is refused.
func TestHelpdeskClaimSingleFlight(t *testing.T) {
	f := storetest.TwoTenants(t)
	s := seedHelpdesk(t, f)
	id := s.caseID[f.A.Slug]
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if err := c.ClaimHelpdeskCase(id, "agent", storetest.Now); err != nil {
			return err
		}
		if err := c.ClaimHelpdeskCase(id, "agent2", storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second claim = %v, want ErrNotFound", err)
		}
		if err := c.CancelHelpdeskCase(id, storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cancel while executing = %v, want ErrNotFound", err)
		}
		return c.FinishHelpdeskCase(id, "failed", storetest.Now, "", "boom")
	})
	if err != nil {
		t.Fatal(err)
	}
	// a failed case can be claimed again
	err = f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.ClaimHelpdeskCase(id, "agent", storetest.Now)
	})
	if err != nil {
		t.Errorf("claim after failure = %v", err)
	}
}

func helpdeskCovered() map[string]bool {
	return map[string]bool{"HelpdeskCases": true, "HelpdeskCase": true, "HelpdeskVerifications": true, // TestIsolation_HelpdeskReads
		"HelpdeskSignals": true, "HelpdeskFindings": true, "HelpdeskFindingsForCase": true,
		"HelpdeskCasesExecutedSince": true, "PlatformUserIDsForIdentity": true, "IdentityHoldsAdminRole": true,
		"InsertHelpdeskCase": true, "InsertHelpdeskVerification": true, "InsertHelpdeskSignal": true, // TestIsolation_HelpdeskWritesScoped
		"InsertHelpdeskFinding": true, "ClaimHelpdeskCase": true, "CancelHelpdeskCase": true,
		"SetHelpdeskSecondApproval": true, "FinishHelpdeskCase": true}
}
