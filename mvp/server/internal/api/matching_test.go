package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The identity-matching API (issue #68): the review queue with masked
// attributes and the rules that fired, decisions with a reason, four eyes,
// reverification, and the settings.

type matchWorld struct {
	t       *testing.T
	f       *storetest.Fixture
	h       http.Handler
	carol   authtest.Login // sponsors
	admin1  authtest.Login
	admin2  authtest.Login
	bobMail string
}

func newMatchWorld(t *testing.T) *matchWorld {
	t.Helper()
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	w := &matchWorld{t: t, f: f, h: h, carol: reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol"),
		admin1: policyAdmin(t, f, f.B.ID, "pa1@b.example"), admin2: policyAdmin(t, f, f.B.ID, "pa2@b.example")}
	if err := f.DB.ReadTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		i, err := c.Identity(f.B.IDs["bob"])
		w.bobMail = *i.Email
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

// invite invites a guest at the address of Bob, an employee, as Carol would.
func (w *matchWorld) invite(email string) {
	w.t.Helper()
	rec := reqDo(w.h, w.carol, "POST", "/api/guests/invitations", inviteJSON(email, "visitor", storetest.Now.AddDate(0, 0, 10), ""))
	if rec.Code != http.StatusCreated {
		w.t.Fatalf("invite: %d %s", rec.Code, rec.Body)
	}
}

type matchList struct {
	Items []struct {
		ID         string `json:"id"`
		IntakeID   string `json:"intake_id"`
		Status     string `json:"status"`
		Subject    struct{ Name, Email string }
		Candidates []struct {
			MatchID  string `json:"match_id"`
			Name     string `json:"name"`
			Email    string `json:"email"`
			Tier     string `json:"tier"`
			Status   string `json:"status"`
			Employee bool   `json:"employee"`
			IAL      int    `json:"ial"`
			Rules    []struct {
				Rule     string            `json:"rule"`
				Why      string            `json:"why"`
				Compared map[string]string `json:"compared"`
			} `json:"rules"`
			SecondReviewer []string `json:"second_reviewer_because"`
		} `json:"candidates"`
	} `json:"items"`
	Count int `json:"count"`
}

func (w *matchWorld) list(l authtest.Login, status string) (matchList, string) {
	w.t.Helper()
	rec := reqDo(w.h, l, "GET", "/api/identity-matches?status="+status, "")
	if rec.Code != 200 {
		w.t.Fatalf("list %s: %d %s", status, rec.Code, rec.Body)
	}
	var out matchList
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		w.t.Fatal(err)
	}
	return out, rec.Body.String()
}

func TestMatchingAPI_QueueDecideFourEyesReverification(t *testing.T) {
	w := newMatchWorld(t)
	w.invite(w.bobMail)
	q, raw := w.list(w.admin1, "review")
	if q.Count != 1 || len(q.Items) != 1 || len(q.Items[0].Candidates) != 1 {
		t.Fatalf("queue: %s", raw)
	}
	it, c := q.Items[0], q.Items[0].Candidates[0]
	// masked: the queue never carries the full name or address of either side
	for _, leak := range []string{w.bobMail, "Gwen", "Guest", "Bob"} {
		if strings.Contains(raw, leak) {
			t.Errorf("the queue shows %q: %s", leak, raw)
		}
	}
	if it.Subject.Name == "" || c.Name == "" || c.Email == "" || c.Tier != "C" || !c.Employee || c.IAL < 2 || len(c.SecondReviewer) == 0 {
		t.Errorf("item = %+v", it)
	}
	if len(c.Rules) != 1 || c.Rules[0].Rule != "verified_email" || c.Rules[0].Why == "" || c.Rules[0].Compared["email"] == "" {
		t.Errorf("rules = %+v", c.Rules)
	}
	path := "/api/identity-matches/" + c.MatchID + "/decide"

	// a reason is required and the decision must be one of three
	if rec := reqDo(w.h, w.admin1, "POST", path, `{"decision":"link","reason":""}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "reason_required") {
		t.Errorf("no reason: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(w.h, w.admin1, "POST", path, `{"decision":"shrug","reason":"x"}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_decision") {
		t.Errorf("bad decision: %d %s", rec.Code, rec.Body)
	}
	// a link into an employee waits for a second reviewer
	rec := reqDo(w.h, w.admin1, "POST", path, `{"decision":"link","reason":"same person: HR confirmed"}`)
	var pend struct {
		Result  string           `json:"result"`
		Request mergeRequestView `json:"request"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pend); err != nil || rec.Code != 202 || pend.Result != "pending_approval" || pend.Request.Status != "pending" {
		t.Fatalf("link: %d %s", rec.Code, rec.Body)
	}
	if pend.Request.Kind != "match_link" || len(pend.Request.Risk) == 0 || pend.Request.MatchID == nil {
		t.Errorf("request = %+v", pend.Request)
	}
	// the same reviewer cannot approve; the list shows it
	reqPath := "/api/identity-merge-requests/" + pend.Request.ID
	if rec := reqDo(w.h, w.admin1, "POST", reqPath+"/approve", `{}`); rec.Code != 403 || !strings.Contains(rec.Body.String(), "second_reviewer_required") {
		t.Errorf("self-approval: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(w.h, w.admin2, "GET", "/api/identity-merge-requests", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), pend.Request.ID) {
		t.Errorf("pending requests: %d %s", rec.Code, rec.Body)
	}
	// the queue says a request is waiting
	if q2, raw := w.list(w.admin2, "review"); len(q2.Items) != 1 || !strings.Contains(raw, `"pending_request":{`) {
		t.Errorf("queue with a pending request: %s", raw)
	}
	// the second reviewer approves: the claimant must re-verify before anything is linked
	rec = reqDo(w.h, w.admin2, "POST", reqPath+"/approve", `{}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"reverification_required"`) || strings.Contains(rec.Body.String(), `"merge":`) {
		t.Fatalf("approval: %d %s", rec.Code, rec.Body)
	}
	if got, _ := w.list(w.admin2, "review"); len(got.Items) != 0 {
		t.Errorf("a decided item is still in the review queue")
	}
	got, _ := w.list(w.admin2, "reverification")
	if len(got.Items) != 1 || got.Items[0].Candidates[0].Status != "reverification" {
		t.Errorf("reverification list: %+v", got)
	}
	if rec := reqDo(w.h, w.admin2, "GET", "/api/identity-merges", ""); strings.Contains(rec.Body.String(), `"merged_id"`) {
		t.Errorf("a merge exists: %s", rec.Body)
	}
	acts := auditActions(t, w.f, w.f.B.ID)
	for _, a := range []string{"identity.match", "identity.merge.request", "identity.merge.approve", "identity.match.reverification_required"} {
		if acts[a] != 1 {
			t.Errorf("audit %s = %d (%v)", a, acts[a], acts)
		}
	}
	if acts["identity.merge"] != 0 {
		t.Error("a merge entry without a merge")
	}
}

func TestMatchingAPI_NewPersonAndReject(t *testing.T) {
	w := newMatchWorld(t)
	w.invite(w.bobMail)
	q, _ := w.list(w.admin1, "review")
	path := "/api/identity-matches/" + q.Items[0].ID + "/decide"
	rec := reqDo(w.h, w.admin1, "POST", path, `{"decision":"new_person","reason":"a different Bob"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"result":"new_person"`) {
		t.Fatalf("new person: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(w.h, w.admin1, "POST", path, `{"decision":"reject","reason":"x"}`); rec.Code != 409 || !strings.Contains(rec.Body.String(), "already_decided") {
		t.Errorf("decided twice: %d %s", rec.Code, rec.Body)
	}
	if d, raw := w.list(w.admin1, "decided"); len(d.Items) != 1 || !strings.Contains(raw, `"status":"new_person"`) {
		t.Errorf("decided list: %s", raw)
	}
	// reject: the invitation is cancelled and the sponsorship ends
	w.invite("guest2-" + w.bobMail)
	w.invite(w.bobMail)
	q, _ = w.list(w.admin1, "review")
	if len(q.Items) != 1 {
		t.Fatalf("queue: %+v", q)
	}
	rec = reqDo(w.h, w.admin1, "POST", "/api/identity-matches/"+q.Items[0].ID+"/decide", `{"decision":"reject","reason":"duplicate request"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"result":"rejected"`) {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body)
	}
	if err := w.f.DB.ReadTenant(t.Context(), w.f.B.ID, func(c *store.TenantTx) error {
		ss, err := c.Sponsorships(store.SponsorshipFilter{})
		revoked := 0
		for _, s := range ss {
			if s.Status == store.SponsorRevoked && s.EndReason != nil && strings.Contains(*s.EndReason, "intake rejected") {
				revoked++
			}
		}
		if revoked != 1 {
			t.Errorf("%d sponsorships revoked by the rejection (%d in all)", revoked, len(ss))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMatchingAPI_NeedsPermissionAndStepUp(t *testing.T) {
	w := newMatchWorld(t)
	w.invite(w.bobMail)
	q, _ := w.list(w.admin1, "review")
	id := q.Items[0].ID
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RoleTenantAdmin} {
		l := signIn(t, w.f.DB, w.f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		for _, rq := range []struct{ method, path, body string }{
			{"GET", "/api/identity-matches", ""},
			{"POST", "/api/identity-matches/" + id + "/decide", `{"decision":"new_person","reason":"x"}`},
			{"GET", "/api/admin/matching", ""},
			{"PUT", "/api/admin/matching", `{"unmerge_window_days":10}`},
		} {
			if rec := reqDo(w.h, l, rq.method, rq.path, rq.body); rec.Code != 403 {
				t.Errorf("%s %s %s: %d", role, rq.method, rq.path, rec.Code)
			}
		}
		if role != auth.RoleViewer && role != auth.RoleOperator && role != auth.RoleAuditor && role != auth.RoleTenantAdmin {
			continue
		}
		if rec := reqDo(w.h, l, "POST", "/api/identity-merge-requests/x/approve", `{}`); rec.Code != 403 {
			t.Errorf("%s approve: %d", role, rec.Code)
		}
	}
	stale := signIn(t, w.f.DB, w.f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := reqDo(w.h, stale, "POST", "/api/identity-matches/"+id+"/decide", `{"decision":"new_person","reason":"x"}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale decide: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(w.h, stale, "PUT", "/api/admin/matching", `{"unmerge_window_days":10}`); rec.Code != 401 {
		t.Errorf("stale settings: %d", rec.Code)
	}
}

// Tenant B cannot read or decide tenant A's matches and requests: A's ids answer
// exactly like missing ones, and A's queue never shows in B's.
func TestMatchingAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	la := policyAdmin(t, f, f.A.ID, "pa1@a.example")
	la2 := policyAdmin(t, f, f.A.ID, "pa2@a.example")
	lb := policyAdmin(t, f, f.B.ID, "pa@b.example")
	carolA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "carol@a.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: ptr(f.A.IDs["carol"])}, authtest.Phr, storetest.Now)
	var bobMail string
	if err := f.DB.ReadTenant(t.Context(), f.A.ID, func(c *store.TenantTx) error {
		i, err := c.Identity(f.A.IDs["bob"])
		bobMail = *i.Email
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rec := reqDo(h, carolA, "POST", "/api/guests/invitations", inviteJSON(bobMail, "visitor", storetest.Now.AddDate(0, 0, 10), "")); rec.Code != http.StatusCreated {
		t.Fatalf("A invite: %d %s", rec.Code, rec.Body)
	}
	rec := reqDo(h, la, "GET", "/api/identity-matches", "")
	var q matchList
	if err := json.Unmarshal(rec.Body.Bytes(), &q); err != nil || len(q.Items) != 1 {
		t.Fatalf("A's queue: %d %s", rec.Code, rec.Body)
	}
	matchID := q.Items[0].ID
	rec = reqDo(h, la, "POST", "/api/identity-matches/"+matchID+"/decide", `{"decision":"link","reason":"same"}`)
	var pend struct {
		Request mergeRequestView `json:"request"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pend)
	if rec.Code != 202 {
		t.Fatalf("A link: %d %s", rec.Code, rec.Body)
	}
	before := storetest.Dump(t, f.DB, f.A.ID)
	missing := "00000000-0000-4000-8000-00000000dead"
	for _, c := range []struct{ name, a, b, body string }{
		{"decide", "/api/identity-matches/" + matchID + "/decide", "/api/identity-matches/" + missing + "/decide", `{"decision":"reject","reason":"x"}`},
		{"approve", "/api/identity-merge-requests/" + pend.Request.ID + "/approve", "/api/identity-merge-requests/" + missing + "/approve", `{}`},
		{"reject", "/api/identity-merge-requests/" + pend.Request.ID + "/reject", "/api/identity-merge-requests/" + missing + "/reject", `{"reason":"x"}`},
	} {
		cross := reqDo(h, lb, "POST", c.a, c.body)
		gone := reqDo(h, lb, "POST", c.b, c.body)
		if cross.Code != 404 || cross.Body.String() != gone.Body.String() {
			t.Errorf("B %s A's id: %d %s (missing: %d %s)", c.name, cross.Code, cross.Body, gone.Code, gone.Body)
		}
	}
	for _, path := range []string{"/api/identity-matches?status=all", "/api/identity-merge-requests?status=all"} {
		if rec := reqDo(h, lb, "GET", path, ""); strings.Contains(rec.Body.String(), matchID) || strings.Contains(rec.Body.String(), pend.Request.ID) {
			t.Errorf("B lists A's rows at %s: %s", path, rec.Body)
		}
	}
	// settings are per tenant
	if rec := reqDo(h, lb, "PUT", "/api/admin/matching", `{"unmerge_window_days":7,"auto_link_tier_b":true}`); rec.Code != 200 {
		t.Fatalf("B settings: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, la, "GET", "/api/admin/matching", ""); !strings.Contains(rec.Body.String(), `"unmerge_window_days":180`) || !strings.Contains(rec.Body.String(), `"auto_link_tier_b":false`) {
		t.Errorf("A's settings after B's: %s", rec.Body)
	}
	// and the approval in A is the other reviewer's, as in any tenant
	if rec := reqDo(h, la2, "POST", "/api/identity-merge-requests/"+pend.Request.ID+"/approve", `{}`); rec.Code != 200 {
		t.Errorf("A approval: %d %s", rec.Code, rec.Body)
	}
	if after := storetest.Dump(t, f.DB, f.A.ID); after == before {
		t.Error("A's own approval changed nothing")
	}
}

func TestMatchingAPI_Settings(t *testing.T) {
	w := newMatchWorld(t)
	rec := reqDo(w.h, w.admin1, "GET", "/api/admin/matching", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"unmerge_window_days":180`) {
		t.Fatalf("defaults: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{`{"unmerge_window_days":0}`, `{"unmerge_window_days":4000}`, `{"unmerge_window_days":30,"extra":1}`} {
		if rec := reqDo(w.h, w.admin1, "PUT", "/api/admin/matching", bad); rec.Code != 422 {
			t.Errorf("%s: %d %s", bad, rec.Code, rec.Body)
		}
	}
	rec = reqDo(w.h, w.admin1, "PUT", "/api/admin/matching", `{"unmerge_window_days":30,"auto_link_tier_b":true,"require_review_tier_a":true}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"unmerge_window_days":30`) || !strings.Contains(rec.Body.String(), `"updated_by"`) {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	if auditActions(t, w.f, w.f.B.ID)["identity.matching.configure"] != 1 {
		t.Error("the change is not in the ledger")
	}
	// the window shows in a merge
	g := w.f.B.IDs
	rec = reqDo(w.h, w.admin1, "POST", fmt.Sprintf("/api/identities/%d/merge", g["dave"]), fmt.Sprintf(`{"into":%d,"reason":"x"}`, g["bob"]))
	if rec.Code != 202 {
		t.Fatalf("merge request: %d %s", rec.Code, rec.Body)
	}
	var pend struct {
		Request mergeRequestView `json:"request"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pend)
	rec = reqDo(w.h, w.admin2, "POST", "/api/identity-merge-requests/"+pend.Request.ID+"/approve", `{}`)
	var appr struct {
		Merge mergeView `json:"merge"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &appr); err != nil || rec.Code != 200 || !appr.Merge.UnmergeBefore.Equal(storetest.Now.Add(30*24*time.Hour)) {
		t.Errorf("approve: %d %s", rec.Code, rec.Body)
	}
}
