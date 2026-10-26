package api

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// A review item on an evaluated edge links to the evaluator's explanation of
// that edge; an item on an edge nothing evaluated has no explanation_id key at
// all, and an evaluated edge of another campaign leaks nowhere (EP-8).
func TestCampaignReviewItemsCarryExplanationID(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	viewer := signIn(t, f.DB, f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)

	var camp int64
	if err := f.DB.InTenant(t.Context(), f.A.ID, func(c *store.TenantTx) error {
		ev, err := c.UpsertEvaluatorEdge("account:900", "perm:901", "grants", storetest.Now,
			store.EdgeEvaluation{ExplanationID: "ex-900-901", Outcome: "allow", Fidelity: "exact"})
		if err != nil || !ev {
			t.Fatalf("UpsertEvaluatorEdge = %v, %v", ev, err)
		}
		if _, err := c.UpsertEvaluatorEdge("account:900", "perm:902", "grants", storetest.Now,
			store.EdgeEvaluation{ExplanationID: "ex-other-campaign", Outcome: "allow", Fidelity: "exact"}); err != nil {
			return err
		}
		e, err := c.EdgeBetween("account:900", "perm:901")
		if err != nil {
			return err
		}
		if camp, err = c.InsertCampaign(&store.ReviewCampaign{Name: "x", CreatedAt: storetest.Now, Status: "open"}); err != nil {
			return err
		}
		for _, edge := range []*int64{&e.ID, nil} {
			it := &store.ReviewItem{CampaignID: camp, IdentityID: f.A.IDs["bob"], EdgeID: edge, EdgeSrc: e.Src, EdgeDst: e.Dst,
				GrantLabel: "g", Reasons: []string{}, Context: []byte(`{}`)}
			if err := c.InsertReviewItem(it); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	rec := serve(h, authed(viewer, "GET", fmt.Sprintf("/api/reviews/campaigns/%d", camp), ""))
	if rec.Code != 200 {
		t.Fatalf("campaign: %d %s", rec.Code, rec.Body)
	}
	var cv struct {
		Items []map[string]any `json:"review_items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cv); err != nil || len(cv.Items) != 2 {
		t.Fatalf("review_items = %v, %v", cv.Items, err)
	}
	if got := cv.Items[0]["explanation_id"]; got != "ex-900-901" {
		t.Errorf("evaluated item explanation_id = %v, want ex-900-901", got)
	}
	if _, has := cv.Items[1]["explanation_id"]; has {
		t.Errorf("an item with no evaluated edge carries explanation_id: %v", cv.Items[1])
	}
}
