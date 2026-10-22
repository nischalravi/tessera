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
	other := signIn(t, f.DB, f.B.ID, authtest.User{Email: "other@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	path := fmt.Sprintf("/api/reviews/items/%d/decision", item.ID)

	rec := schedDo(h, self, "POST", path, `{"decision":"keep"}`)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"self_review"`) {
		t.Fatalf("self decision: %d %s", rec.Code, rec.Body)
	}
	if rec := schedDo(h, other, "POST", path, `{"decision":"keep"}`); rec.Code != 200 {
		t.Fatalf("another reviewer: %d %s", rec.Code, rec.Body)
	}
}
