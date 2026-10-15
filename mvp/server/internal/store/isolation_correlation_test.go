package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Correlation isolation (issue #160): a tenant sees and changes only its own
// account decisions and merges; another tenant's account, identity, merge
// and user ids look nonexistent, and rows naming them are refused by the
// guard triggers.

type corrRows struct {
	user  *store.PlatformUser
	merge string
	acct  int64 // the pinned account
	ident int64 // alice
	bob   int64
}

func seedCorrRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) corrRows {
	t.Helper()
	r := corrRows{merge: "merge-" + tag, acct: tn.IDs["acct:okta:alice"], ident: tn.IDs["alice"], bob: tn.IDs["bob"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.user = &store.PlatformUser{DisplayName: "reviewer " + tag, CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		if err := c.PutAccountLink(&store.AccountLink{AccountID: r.acct, Decision: store.LinkDecisionLink,
			IdentityID: &r.ident, Reason: "checked", DecidedBy: r.user.ID.String(), DecidedAt: storetest.Now}); err != nil {
			return err
		}
		return c.InsertIdentityMerge(&store.IdentityMerge{ID: r.merge, SurvivorID: r.ident, MergedID: r.bob,
			MergedStatus: "active", Moves: []store.MergeMove{}, Reason: "duplicate", MergedBy: r.user.ID.String(),
			MergedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func corrFixture(t *testing.T) (*storetest.Fixture, corrRows, corrRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedCorrRows(t, f.DB, f.A, "a"), seedCorrRows(t, f.DB, f.B, "b")
}

func TestIsolation_CorrelationReads(t *testing.T) {
	f, a, b := corrFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		links, err := c.AccountLinks()
		if err != nil || len(links) != 1 || links[0].AccountID != b.acct {
			t.Errorf("AccountLinks = %v, %v", links, err)
		}
		if _, err := c.AccountLink(a.acct); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AccountLink(A's account) = %v", err)
		}
		if to, err := c.AccountLinksTo(a.ident); err != nil || len(to) != 0 {
			t.Errorf("AccountLinksTo(A's identity) = %v, %v", to, err)
		}
		ms, err := c.IdentityMerges()
		if err != nil || len(ms) != 1 || ms[0].ID != b.merge {
			t.Errorf("IdentityMerges = %v, %v", ms, err)
		}
		if open, err := c.OpenIdentityMerges(); err != nil || len(open) != 1 || open[0].ID != b.merge {
			t.Errorf("OpenIdentityMerges = %v, %v", open, err)
		}
		if _, err := c.IdentityMerge(a.merge); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("IdentityMerge(A's) = %v", err)
		}
		surv, err := c.MergeSurvivors()
		if err != nil || len(surv) != 1 || surv[b.bob] != b.ident {
			t.Errorf("MergeSurvivors = %v, %v", surv, err)
		}
		if ids, err := c.DelegationIDsByPrincipal(a.bob); err != nil || len(ids) != 0 {
			t.Errorf("DelegationIDsByPrincipal(A's bob) = %v, %v", ids, err)
		}
		if n, err := c.PlatformUsersForIdentity(a.ident); err != nil || n != 0 {
			t.Errorf("PlatformUsersForIdentity(A's) = %d, %v", n, err)
		}
		if _, err := c.MoveRef(store.MergeMove{Table: "accounts", ID: a.acct, Column: "identity_id"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MoveRef(A's account) = %v", err)
		}
		if _, err := c.MoveRef(store.MergeMove{Table: "account_links", ID: a.acct, Column: "identity_id"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MoveRef(A's link) = %v", err)
		}
		return nil
	})
}

// corrMutations change one of A's rows; run in B they must fail with
// ErrNotFound (or the cross-tenant guard) and leave A alone.
var corrMutations = map[string]func(c *store.TenantTx, a, b corrRows) error{
	"DeleteAccountLink":  func(c *store.TenantTx, a, _ corrRows) error { return c.DeleteAccountLink(a.acct) },
	"SetAccountIdentity": func(c *store.TenantTx, a, b corrRows) error { return c.SetAccountIdentity(a.acct, &b.ident) },
	"SetIdentityStatus":  func(c *store.TenantTx, a, _ corrRows) error { return c.SetIdentityStatus(a.ident, "merged") },
	"MarkUnmerged": func(c *store.TenantTx, a, b corrRows) error {
		return c.MarkUnmerged(a.merge, b.user.ID.String(), "x", storetest.Now)
	},
	"ApplyMove": func(c *store.TenantTx, a, b corrRows) error {
		return c.ApplyMove(store.MergeMove{Table: "accounts", ID: a.acct, Column: "identity_id"}, b.ident)
	},
	// B's own row pointed at A's identity: the guard trigger refuses it
	"PutAccountLink": func(c *store.TenantTx, a, b corrRows) error {
		return c.PutAccountLink(&store.AccountLink{AccountID: b.acct, Decision: store.LinkDecisionLink, IdentityID: &a.ident,
			Reason: "x", DecidedBy: b.user.ID.String(), DecidedAt: storetest.Now})
	},
	"InsertIdentityMerge": func(c *store.TenantTx, a, b corrRows) error {
		return c.InsertIdentityMerge(&store.IdentityMerge{ID: "x-merge", SurvivorID: b.ident, MergedID: a.bob,
			MergedStatus: "active", Moves: []store.MergeMove{}, Reason: "x", MergedBy: b.user.ID.String(), MergedAt: storetest.Now})
	},
}

func TestIsolation_CorrelationMutationsScoped(t *testing.T) {
	for name, fn := range corrMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := corrFixture(t)
			before := corrDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := corrDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A:\nbefore %s\nafter  %s", name, before, after)
			}
		})
	}
}

// A reviewer of another tenant cannot be recorded as a decider.
func TestIsolation_CorrelationForeignActorRefused(t *testing.T) {
	f, a, b := corrFixture(t)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.PutAccountLink(&store.AccountLink{AccountID: b.acct, Decision: store.LinkDecisionNotPerson,
			Reason: "x", DecidedBy: a.user.ID.String(), DecidedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("foreign decided_by = %v, want ErrCrossTenant", err)
	}
}

// Merge records are append-only: only the unmerge columns change, once.
func TestCorrelation_MergeRecordAppendOnly(t *testing.T) {
	f, a, _ := corrFixture(t)
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.MarkUnmerged(a.merge, a.user.ID.String(), "wrong", storetest.Now); err != nil {
			t.Fatal(err)
		}
		if err := c.MarkUnmerged(a.merge, a.user.ID.String(), "again", storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second unmerge = %v, want ErrNotFound", err)
		}
		m, err := c.IdentityMerge(a.merge)
		if err != nil || m.UnmergedAt == nil || *m.UnmergeReason != "wrong" {
			t.Errorf("merge = %+v, %v", m, err)
		}
		return nil
	})
}

func corrDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		links, err := c.AccountLinks()
		if err != nil {
			return err
		}
		ms, err := c.IdentityMerges()
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{links, ms})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func correlationCovered() map[string]bool {
	out := map[string]bool{}
	for k := range corrMutations {
		out[k] = true
	}
	for _, k := range []string{"AccountLinks", "AccountLink", "AccountLinksTo", "IdentityMerges", "OpenIdentityMerges",
		"IdentityMerge", "MergeSurvivors", "DelegationIDsByPrincipal", "PlatformUsersForIdentity", "MoveRef"} {
		out[k] = true // TestIsolation_CorrelationReads
	}
	return out
}
