package api

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// A reviewer cannot decide an item about their own identity: 403 self_review,
// nothing is recorded as decided, and another reviewer still can (issue #434).
func TestReviewDecideSelfReviewAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	ps, err := srv.policies()
	if err != nil {
		t.Fatal(err)
	}
	var item *store.ReviewItem
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		camp, err := reviews.GenerateCampaign(c, storetest.Now, "self", 60, ps)
		if err != nil {
			return err
		}
		items, err := c.CampaignItems(camp)
		if err == nil && len(items) > 0 {
			item = items[0]
		}
		return err
	}); err != nil || item == nil {
		t.Fatalf("no item to decide: %v", err)
	}
	subject := item.IdentityID
	self := signIn(t, f.DB, f.B.ID, authtest.User{Email: "self@b.example", Roles: []auth.Role{auth.RoleOperator},
		IdentityID: &subject}, authtest.Phr, storetest.Now)
	other := signIn(t, f.DB, f.B.ID, authtest.User{Email: "other@b.example", Roles: []auth.Role{auth.RoleOperator},
		IdentityID: ensureIdentity(t, f.DB, f.B.ID, "other-reviewer", "other-reviewer", storetest.Now)}, authtest.Phr, storetest.Now)
	path := fmt.Sprintf("/api/reviews/items/%d/decision", item.ID)

	rec := schedDo(h, self, "POST", path, `{"decision":"keep"}`)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"self_review"`) {
		t.Fatalf("self decision: %d %s", rec.Code, rec.Body)
	}
	if rec := schedDo(h, other, "POST", path, `{"decision":"keep"}`); rec.Code != 200 {
		t.Fatalf("another reviewer: %d %s", rec.Code, rec.Body)
	}
}

// Issues #439 and #440: a decider whose account has no linked identity is
// refused (403 reviewer_unlinked), and the QA route refuses the subject
// (403 self_review). Every refusal is audited and changes nothing.
func TestReviewDecideRefusalsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	roles := []auth.Role{auth.RolePolicyAdmin}
	unlinked := signIn(t, f.DB, f.B.ID, authtest.User{Email: "unlinked@b.example", Roles: roles}, authtest.Phr, storetest.Now)
	bob := f.B.IDs["bob"] // the subject of the fixture's QA-sampled auto-decision
	subject := signIn(t, f.DB, f.B.ID, authtest.User{Email: "bob-rev@b.example", Roles: roles, IdentityID: &bob}, authtest.Phr, storetest.Now)
	item := fmt.Sprintf("/api/reviews/items/%d/decision", f.B.IDs["item"])
	qa := fmt.Sprintf("/api/reviews/qa/%d/decision", f.B.IDs["qa"])

	for _, tc := range []struct {
		name, path, code string
		by               authtest.Login
	}{
		{"unlinked, item", item, "reviewer_unlinked", unlinked},
		{"unlinked, QA", qa, "reviewer_unlinked", unlinked},
		{"subject, QA", qa, "self_review", subject},
	} {
		before := auditCount(t, f, "review.decide.refused")
		rec := schedDo(h, tc.by, "POST", tc.path, `{"decision":"keep"}`)
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"`+tc.code+`"`) {
			t.Errorf("%s: %d %s, want 403 %s", tc.name, rec.Code, rec.Body, tc.code)
		}
		if n := auditCount(t, f, "review.decide.refused"); n != before+1 {
			t.Errorf("%s: %d review.decide.refused events, want %d", tc.name, n, before+1)
		}
	}
	if err := f.DB.ReadTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		it, err := c.Item(f.B.IDs["item"])
		if err != nil {
			return err
		}
		if it.Decision != nil && *it.Decision != "" {
			t.Errorf("the refused item decision was recorded: %q", *it.Decision)
		}
		ad, err := c.AutoDecision(f.B.IDs["qa"])
		if err == nil && ad.QADecision != nil {
			t.Errorf("the refused QA decision was recorded: %q", *ad.QADecision)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
