package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Consult, answer, reassign, lock and close over the API.
func TestReviewActionsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	item, camp := f.B.IDs["item"], f.B.IDs["campaign"]
	var subject, current int64
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		it, err := c.Item(item)
		subject = it.IdentityID
		if it.ReviewerID != nil {
			current = *it.ReviewerID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	pick := func(skip ...int64) int64 {
		for _, n := range []string{"alice", "bob", "carol"} {
			id := f.B.IDs[n]
			ok := id != subject
			for _, s := range skip {
				ok = ok && id != s
			}
			if ok {
				return id
			}
		}
		t.Fatal("no person left")
		return 0
	}
	consultant := pick()
	newReviewer := pick(current)
	bystander := pick(consultant)
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	answerer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "c@b.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &consultant}, authtest.Phr, now)
	stranger := signIn(t, f.DB, f.B.ID, authtest.User{Email: "s@b.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &bystander}, authtest.Phr, now)
	// both people need a sign-in account linked to them to be asked
	itemPath := fmt.Sprintf("/api/reviews/items/%d", item)

	if rec := reqDo(h, stranger, "POST", itemPath+"/consult", fmt.Sprintf(`{"identity_id":%d,"question":"x"}`, consultant)); rec.Code != 403 {
		t.Errorf("a viewer consults: %d", rec.Code)
	}
	rec := reqDo(h, admin, "POST", itemPath+"/consult", fmt.Sprintf(`{"identity_id":%d,"question":"is this needed?"}`, consultant))
	var ev reviewEventView
	if err := json.Unmarshal(rec.Body.Bytes(), &ev); err != nil || rec.Code != 201 || ev.Target == nil || ev.Target.ID != consultant {
		t.Fatalf("consult: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", itemPath+"/consult", fmt.Sprintf(`{"identity_id":%d,"question":"x"}`, subject)); rec.Code != 422 {
		t.Errorf("consult the subject: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, answerer, "GET", "/api/reviews/consultations", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "is this needed?") {
		t.Errorf("my consultations: %d %s", rec.Code, rec.Body)
	}
	ans := fmt.Sprintf("/api/reviews/consultations/%d/answer", ev.ID)
	if rec := reqDo(h, stranger, "POST", ans, `{"answer":"hm"}`); rec.Code != 404 {
		t.Errorf("another person answers: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, answerer, "POST", ans, `{"answer":"keep it"}`); rec.Code != 201 {
		t.Errorf("answer: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "GET", itemPath+"/events", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "keep it") {
		t.Errorf("events: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", itemPath+"/reassign", fmt.Sprintf(`{"identity_id":%d,"reason":"owns it"}`, newReviewer)); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), fmt.Sprintf(`"reviewer_id":%d`, newReviewer)) {
		t.Errorf("reassign: %d %s", rec.Code, rec.Body)
	}
	campPath := fmt.Sprintf("/api/reviews/campaigns/%d", camp)
	if rec := reqDo(h, admin, "POST", campPath+"/lock", `{}`); rec.Code != 422 {
		t.Errorf("lock without a reason: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "POST", campPath+"/lock", `{"reason":"audit"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"locked"`) {
		t.Fatalf("lock: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "POST", itemPath+"/decision", `{"decision":"keep"}`)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "campaign_locked") {
		t.Errorf("decide while locked: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", campPath+"/unlock", ``); rec.Code != 200 {
		t.Errorf("unlock: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", campPath+"/close", `{"reason":"out of scope"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"closed"`) {
		t.Errorf("close: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", campPath+"/unlock", ``); rec.Code != 409 {
		t.Errorf("unlock a closed review: %d", rec.Code)
	}
	acts := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"review.consult", "review.consult.answer", "review.reassign", "review.lock", "review.unlock", "review.close"} {
		if acts[a] != 1 {
			t.Errorf("audit %s = %d (%v)", a, acts[a], acts)
		}
	}
}
