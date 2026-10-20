package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Matching isolation (issue #68): a tenant sees and changes only its own match
// results, merge requests, matching settings and claim links; another tenant's
// ids look nonexistent, and a row naming another tenant's intake, person,
// reviewer, result or session is refused by the guard triggers.

type matchRows struct {
	claimRows
	user         *store.PlatformUser
	second       *store.PlatformUser
	match, merge string
	candidate    int64
	link         string
	loginTxn     string
}

func seedMatching(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) matchRows {
	t.Helper()
	r := matchRows{claimRows: seedClaim(t, db, tn, tag), match: "match-" + tag, merge: "mreq-" + tag, candidate: tn.IDs["bob"],
		link: "link-" + tag, loginTxn: "txn-" + tag}
	now := storetest.Now
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.user = &store.PlatformUser{DisplayName: "reviewer " + tag, CreatedAt: now}
		r.second = &store.PlatformUser{DisplayName: "second " + tag, CreatedAt: now}
		for _, u := range []*store.PlatformUser{r.user, r.second} {
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
		}
		if err := c.InsertMatchResult(&store.MatchResult{ID: r.match, IntakeID: r.intake, SubjectID: &r.guest, CandidateID: &r.candidate,
			Tier: "C", Score: 0.6, Rules: `{"rules":[{"rule":"verified_email"}]}`, Outcome: store.MatchOutcomeSuspected,
			Status: store.MatchReview, CreatedAt: now}); err != nil {
			return err
		}
		if err := c.InsertMergeRequest(&store.MergeRequest{ID: r.merge, Kind: store.MergeKindMatchLink, SurvivorID: r.candidate,
			MergedID: r.guest, MatchID: &r.match, Reason: "same person " + tag, Risk: `["employee"]`, RequestedBy: r.user.ID.String(),
			RequestedAt: now}); err != nil {
			return err
		}
		if err := c.PutMatchingSettings(store.MatchingSettings{AutoLinkTierB: true, UnmergeWindowDays: 90}, r.user.ID.String(), now); err != nil {
			return err
		}
		return c.InsertClaimLink(&store.ClaimLink{ID: r.link, SessionIDHash: r.session, IntakeID: r.intake, LoginTxnID: r.loginTxn, CreatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func matchFixture(t *testing.T) (*storetest.Fixture, matchRows, matchRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedMatching(t, f.DB, f.A, "a"), seedMatching(t, f.DB, f.B, "b")
}

func matchDump(t *testing.T, db *store.DB, tid tenancy.ID, r matchRows) string {
	t.Helper()
	out := claimDump(t, db, tid, r.claimRows)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		ms, err := c.MatchResults(store.MatchFilter{})
		if err != nil {
			return err
		}
		qs, err := c.MergeRequests("")
		if err != nil {
			return err
		}
		st, err := c.MatchingSettings()
		if err != nil {
			return err
		}
		l, err := c.ClaimLinkByTxn(r.loginTxn)
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{ms, qs, st, l})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIsolation_MatchingReads(t *testing.T) {
	f, a, b := matchFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.MatchResult(a.match); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MatchResult(A's) = %v", err)
		}
		if x, err := c.MatchResult(b.match); err != nil || x.Status != store.MatchReview {
			t.Errorf("MatchResult(B's) = %+v, %v", x, err)
		}
		if xs, err := c.MatchResults(store.MatchFilter{Intake: a.intake}); err != nil || len(xs) != 0 {
			t.Errorf("MatchResults(A's intake) = %v, %v", xs, err)
		}
		if xs, err := c.MatchResults(store.MatchFilter{Status: store.MatchReview}); err != nil || len(xs) != 1 || xs[0].ID != b.match {
			t.Errorf("MatchResults(review) = %v, %v", xs, err)
		}
		if _, err := c.MergeRequest(a.merge); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MergeRequest(A's) = %v", err)
		}
		if xs, err := c.MergeRequests(store.MergeReqPending); err != nil || len(xs) != 1 || xs[0].ID != b.merge {
			t.Errorf("MergeRequests = %v, %v", xs, err)
		}
		if _, err := c.PendingMergeRequestFor(a.guest); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("PendingMergeRequestFor = %v", err)
		}
		if s, err := c.MatchingSettings(); err != nil || s.UnmergeWindowDays != 90 || !s.AutoLinkTierB {
			t.Errorf("MatchingSettings = %+v, %v", s, err)
		}
		if _, err := c.ClaimLinkByTxn(a.loginTxn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ClaimLinkByTxn(A's) = %v", err)
		}
		if _, err := c.LifecycleRowID(a.sponsor); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("LifecycleRowID = %v", err)
		}
		return nil
	})
}

var matchMutations = map[string]func(c *store.TenantTx, a, b matchRows) error{
	"DecideMatchResult": func(c *store.TenantTx, a, b matchRows) error {
		by := b.user.ID.String()
		now := storetest.Now
		return c.DecideMatchResult(&store.MatchResult{ID: a.match, Status: store.MatchRejected, DecidedBy: &by, DecidedAt: &now})
	},
	"DecideMergeRequest": func(c *store.TenantTx, a, b matchRows) error {
		return c.DecideMergeRequest(a.merge, store.MergeReqApproved, b.second.ID.String(), nil, nil, storetest.Now)
	},
	"FinishClaimLink": func(c *store.TenantTx, a, _ matchRows) error {
		return c.FinishClaimLink(a.link, store.ClaimLinkLinked, storetest.Now)
	},
	"SetIntakeStatus": func(c *store.TenantTx, a, _ matchRows) error {
		return c.SetIntakeStatus(a.intake, store.IntakeRejected)
	},
	"InsertMatchResult/A's intake": func(c *store.TenantTx, a, b matchRows) error {
		return c.InsertMatchResult(&store.MatchResult{ID: uuid.NewString(), IntakeID: a.intake, SubjectID: &b.guest, CandidateID: &b.candidate,
			Tier: "C", Rules: "{}", Outcome: "review", Status: store.MatchReview, CreatedAt: storetest.Now})
	},
	"InsertMatchResult/A's candidate": func(c *store.TenantTx, a, b matchRows) error {
		return c.InsertMatchResult(&store.MatchResult{ID: uuid.NewString(), IntakeID: b.intake, SubjectID: &b.guest, CandidateID: &a.candidate,
			Tier: "C", Rules: "{}", Outcome: "review", Status: store.MatchReview, CreatedAt: storetest.Now})
	},
	"InsertMatchResult/A's reviewer": func(c *store.TenantTx, a, b matchRows) error {
		by, now := a.user.ID.String(), storetest.Now
		return c.InsertMatchResult(&store.MatchResult{ID: uuid.NewString(), IntakeID: b.intake, Tier: "D", Rules: "{}", Outcome: "new",
			Status: store.MatchNewPerson, DecidedBy: &by, DecidedAt: &now, CreatedAt: now})
	},
	"InsertMergeRequest/A's person": func(c *store.TenantTx, a, b matchRows) error {
		return c.InsertMergeRequest(&store.MergeRequest{ID: uuid.NewString(), Kind: store.MergeKindMerge, SurvivorID: a.candidate,
			MergedID: b.sponsor, Reason: "x", Risk: "[]", RequestedBy: b.user.ID.String(), RequestedAt: storetest.Now})
	},
	"InsertMergeRequest/A's requester": func(c *store.TenantTx, a, b matchRows) error {
		return c.InsertMergeRequest(&store.MergeRequest{ID: uuid.NewString(), Kind: store.MergeKindMerge, SurvivorID: b.candidate,
			MergedID: b.sponsor, Reason: "x", Risk: "[]", RequestedBy: a.user.ID.String(), RequestedAt: storetest.Now})
	},
	"InsertMergeRequest/A's result": func(c *store.TenantTx, a, b matchRows) error {
		return c.InsertMergeRequest(&store.MergeRequest{ID: uuid.NewString(), Kind: store.MergeKindMatchLink, SurvivorID: b.candidate,
			MergedID: b.sponsor, MatchID: &a.match, Reason: "x", Risk: "[]", RequestedBy: b.user.ID.String(), RequestedAt: storetest.Now})
	},
	"PutMatchingSettings/A's user": func(c *store.TenantTx, a, _ matchRows) error {
		return c.PutMatchingSettings(store.MatchingSettings{UnmergeWindowDays: 30}, a.user.ID.String(), storetest.Now)
	},
	"InsertClaimLink/A's session": func(c *store.TenantTx, a, b matchRows) error {
		return c.InsertClaimLink(&store.ClaimLink{ID: uuid.NewString(), SessionIDHash: a.session, IntakeID: b.intake,
			LoginTxnID: uuid.NewString(), CreatedAt: storetest.Now})
	},
	"InsertClaimLink/A's intake": func(c *store.TenantTx, a, b matchRows) error {
		return c.InsertClaimLink(&store.ClaimLink{ID: uuid.NewString(), SessionIDHash: b.session, IntakeID: a.intake,
			LoginTxnID: uuid.NewString(), CreatedAt: storetest.Now})
	},
}

func TestIsolation_MatchingMutationsScoped(t *testing.T) {
	for name, fn := range matchMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := matchFixture(t)
			before := matchDump(t, f.DB, f.A.ID, a)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := matchDump(t, f.DB, f.A.ID, a); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
	// settings are per tenant: B's save does not touch A's
	f, a, b := matchFixture(t)
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.PutMatchingSettings(store.MatchingSettings{UnmergeWindowDays: 30}, b.user.ID.String(), storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if s, err := c.MatchingSettings(); err != nil || s.UnmergeWindowDays != 90 {
			t.Errorf("A's settings after B's save = %+v, %v", s, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = a
}

// The schema's own rules: a different person approves, a decision is final, one
// pending request per person, bounded settings, a finished claim link is final.
func TestMatching_SchemaRules(t *testing.T) {
	f, _, b := matchFixture(t)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		// the requester cannot approve their own request
		if err := c.DecideMergeRequest(b.merge, store.MergeReqApproved, b.user.ID.String(), nil, nil, now); err == nil {
			t.Error("a self-approval was accepted")
		}
		// a second request for the same person while one is pending
		if err := c.InsertMergeRequest(&store.MergeRequest{ID: "dup", Kind: store.MergeKindMerge, SurvivorID: b.candidate, MergedID: b.guest,
			Reason: "again", Risk: "[]", RequestedBy: b.second.ID.String(), RequestedAt: now}); err == nil {
			t.Error("two pending requests for one person were accepted")
		}
		if err := c.DecideMergeRequest(b.merge, store.MergeReqApproved, b.second.ID.String(), nil, nil, now); err != nil {
			t.Errorf("a second reviewer's approval: %v", err)
		}
		if err := c.DecideMergeRequest(b.merge, store.MergeReqRejected, b.second.ID.String(), nil, nil, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a decided request was decided again: %v", err)
		}
		// settings stay bounded
		for _, days := range []int{0, -1, 4000} {
			if err := c.PutMatchingSettings(store.MatchingSettings{UnmergeWindowDays: days}, b.user.ID.String(), now); err == nil {
				t.Errorf("an unmerge window of %d days was accepted", days)
			}
		}
		// a decided result is final
		by := b.user.ID.String()
		if err := c.DecideMatchResult(&store.MatchResult{ID: b.match, Status: store.MatchRejected, DecidedBy: &by, DecidedAt: &now}); err != nil {
			t.Fatal(err)
		}
		if err := c.DecideMatchResult(&store.MatchResult{ID: b.match, Status: store.MatchLinked, DecidedBy: &by, DecidedAt: &now}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a decided result was decided again: %v", err)
		}
		// a claim link is finished once
		if err := c.FinishClaimLink(b.link, store.ClaimLinkContinued, now); err != nil {
			t.Fatal(err)
		}
		if err := c.FinishClaimLink(b.link, store.ClaimLinkLinked, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a finished claim link was finished again: %v", err)
		}
		// a tier D result names no candidate and a candidate needs a tier above D
		if err := c.InsertMatchResult(&store.MatchResult{ID: "d1", IntakeID: b.intake, CandidateID: &b.candidate, Tier: "D", Rules: "{}",
			Outcome: "new", Status: store.MatchNewPerson, DecidedAt: &now, CreatedAt: now}); err == nil {
			t.Error("a tier D result with a candidate was accepted")
		}
		if err := c.InsertMatchResult(&store.MatchResult{ID: "c1", IntakeID: b.intake, Tier: "C", Rules: "{}", Outcome: "review",
			Status: store.MatchReview, CreatedAt: now}); err == nil {
			t.Error("a tier C result without a candidate was accepted")
		}
		return nil
	})
}

func matchingCovered() map[string]bool {
	out := map[string]bool{}
	for k := range matchMutations {
		out[k] = true
	}
	for _, k := range []string{"MatchResult", "MatchResults", "MergeRequest", "MergeRequests", "PendingMergeRequestFor", "MatchingSettings",
		"ClaimLinkByTxn", "LifecycleRowID", "InsertMatchResult", "InsertMergeRequest", "PutMatchingSettings", "InsertClaimLink",
		"DecideMatchResult", "DecideMergeRequest", "FinishClaimLink", "SetIntakeStatus"} {
		out[k] = true // TestIsolation_MatchingReads, and the writes in the seeds and mutation cases
	}
	return out
}
