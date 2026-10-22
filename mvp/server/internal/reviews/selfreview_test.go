package reviews_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// linkUser adds an active platform user linked to the identity.
func linkUser(t *testing.T, db *testkit.DB, ident int64) uuid.UUID {
	t.Helper()
	u := &store.PlatformUser{DisplayName: "linked", IdentityID: &ident, CreatedAt: testkit.Now}
	testkit.Write(t, db, func(c *store.TenantTx) error { return c.InsertPlatformUser(u) })
	return u.ID
}

// Issue #434: nobody decides an item about themselves, whichever of their
// linked users they use, through either entry point.
func TestDecideRefusesSelfReview(t *testing.T) {
	tests := []struct {
		name    string
		viaItem bool // DecideItem (the API path) instead of Decide
		second  bool // a second user linked to the same identity decides
		other   bool // an unrelated user decides
		wantErr bool
	}{
		{"subject's own user, Decide", false, false, false, true},
		{"subject's own user, DecideItem", true, false, false, true},
		{"second linked user, Decide", false, true, false, true},
		{"second linked user, DecideItem", true, true, false, true},
		{"unrelated user may decide", true, false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := testkit.Demo(t)
			var item *store.ReviewItem
			testkit.Read(t, db, func(c *store.TenantTx) error {
				items, err := c.CampaignItems(1)
				if err == nil {
					item = items[0]
				}
				return err
			})
			first := linkUser(t, db, item.IdentityID)
			by := first
			if tc.second {
				by = linkUser(t, db, item.IdentityID)
			}
			if tc.other {
				var other int64
				testkit.Read(t, db, func(c *store.TenantTx) error {
					m, _, err := c.IdentityMap()
					for id := range m {
						if id != item.IdentityID {
							other = id
						}
					}
					return err
				})
				by = linkUser(t, db, other)
			}
			ref := store.UserRef{ID: by, Display: "rev"}
			testkit.Write(t, db, func(c *store.TenantTx) error {
				var err error
				if tc.viaItem {
					_, _, err = reviews.DecideItem(c, testkit.Now, item.ID, "keep", ref, nil, "")
				} else {
					_, err = reviews.Decide(c, testkit.Now, item.ID, "keep", ref, nil)
				}
				if got := errors.Is(err, reviews.ErrSelfReview); got != tc.wantErr {
					t.Errorf("ErrSelfReview = %v (%v), want %v", got, err, tc.wantErr)
				}
				if !tc.wantErr && err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return nil
			})
			testkit.Read(t, db, func(c *store.TenantTx) error {
				it, err := c.Item(item.ID)
				if err != nil {
					return err
				}
				if decided := it.Decision != nil && *it.Decision != ""; decided == tc.wantErr {
					t.Errorf("item decided = %v after the call, want %v", decided, !tc.wantErr)
				}
				return nil
			})
		})
	}
}

// Issue #434: when the only assigned reviewer is the subject, the item goes
// to the review type's fallback reviewer instead.
func TestGenerateReassignsSelfAssignedItems(t *testing.T) {
	db := testkit.Demo(t)
	var subject, fallback int64
	var people map[int64]*store.Identity
	testkit.Read(t, db, func(c *store.TenantTx) error {
		items, err := c.CampaignItems(1)
		if err != nil {
			return err
		}
		subject = items[0].IdentityID
		people, _, err = c.IdentityMap()
		return err
	})
	for id, p := range people {
		if id != subject && p.Status == "active" {
			fallback = id
			break
		}
	}
	set := reviews.DefaultTypeSettings(reviews.TypeApplicationOwner)
	set.ReviewerSource, set.ReviewerID, set.FallbackID = reviews.SourceFixed, &subject, &fallback
	testkit.Write(t, db, func(c *store.TenantTx) error {
		r, err := reviews.NewResolver(c, set, people)
		if err != nil {
			return err
		}
		id, err := reviews.GenerateScopedCampaign(c, testkit.Now, "self", 60, testkit.Policies(t), reviews.Scope{Resolver: r})
		if err != nil {
			return err
		}
		items, err := c.CampaignItems(id)
		if err != nil {
			return err
		}
		var onSubject int
		for _, it := range items {
			if it.ReviewerID != nil && *it.ReviewerID == it.IdentityID {
				t.Errorf("item %d is assigned to its own subject %d", it.ID, it.IdentityID)
			}
			if it.IdentityID == subject {
				onSubject++
				if it.ReviewerID == nil || *it.ReviewerID != fallback {
					t.Errorf("item %d about the fixed reviewer: reviewer = %v, want fallback %d", it.ID, it.ReviewerID, fallback)
				}
			}
		}
		if onSubject == 0 {
			t.Skip("the subject has no item in the generated campaign")
		}
		return nil
	})
}

// unlinkedUser adds an active platform user with no linked identity (what
// sign-in creates until an admin links it).
func unlinkedUser(t *testing.T, db *testkit.DB) store.UserRef {
	t.Helper()
	u := &store.PlatformUser{DisplayName: "unlinked", CreatedAt: testkit.Now}
	testkit.Write(t, db, func(c *store.TenantTx) error { return c.InsertPlatformUser(u) })
	return store.UserRef{ID: u.ID, Display: "unlinked"}
}

// Issue #439: a platform user with no linked identity cannot decide: the guard
// cannot prove they are not the subject. Nothing is recorded as decided.
func TestDecideRefusesUnlinkedReviewer(t *testing.T) {
	for _, via := range []string{"Decide", "DecideItem"} {
		t.Run(via, func(t *testing.T) {
			db := testkit.Demo(t)
			by := unlinkedUser(t, db)
			testkit.Write(t, db, func(c *store.TenantTx) error {
				var err error
				if via == "Decide" {
					_, err = reviews.Decide(c, testkit.Now, 1, "keep", by, nil)
				} else {
					_, _, err = reviews.DecideItem(c, testkit.Now, 1, "keep", by, nil, "")
				}
				if !errors.Is(err, reviews.ErrReviewerUnlinked) {
					t.Errorf("err = %v, want ErrReviewerUnlinked", err)
				}
				it, ierr := c.Item(1)
				if ierr == nil && it.Decision != nil && *it.Decision != "" {
					t.Errorf("item decided as %q", *it.Decision)
				}
				return nil
			})
		})
	}
	t.Run("no user (the scheduler) still decides", func(t *testing.T) {
		db := testkit.Demo(t)
		testkit.Write(t, db, func(c *store.TenantTx) error {
			if _, err := reviews.Decide(c, testkit.Now, 1, "keep", store.UserRef{}, nil); err != nil {
				t.Errorf("scheduler decision: %v", err)
			}
			return nil
		})
	})
}

// Issues #439 and #440: QA decisions have the same guard: the subject of the
// auto-decision cannot QA their own grant, and an unlinked user cannot QA.
func TestQADecideRefusesSelfAndUnlinked(t *testing.T) {
	db := testkit.Demo(t)
	var ad *store.AutoDecision
	testkit.Read(t, db, func(c *store.TenantTx) error {
		autos, err := c.AutoDecisions(seedCampaign)
		for _, a := range autos {
			if a.QASample && ad == nil {
				ad = a
			}
		}
		return err
	})
	if ad == nil {
		t.Fatal("the demo campaign needs a QA-sampled auto-decision")
	}
	self := store.UserRef{ID: linkUser(t, db, ad.IdentityID), Display: "subject"}
	unlinked := unlinkedUser(t, db)
	testkit.Write(t, db, func(c *store.TenantTx) error {
		if _, err := reviews.QADecide(c, testkit.Now, ad.ID, "keep", self, nil); !errors.Is(err, reviews.ErrSelfReview) {
			t.Errorf("subject's own QA: %v, want ErrSelfReview", err)
		}
		if _, err := reviews.QADecide(c, testkit.Now, ad.ID, "keep", unlinked, nil); !errors.Is(err, reviews.ErrReviewerUnlinked) {
			t.Errorf("unlinked QA: %v, want ErrReviewerUnlinked", err)
		}
		got, err := c.AutoDecision(ad.ID)
		if err == nil && got.QADecision != nil {
			t.Errorf("a refused QA decision was recorded: %v", *got.QADecision)
		}
		return nil
	})
}
