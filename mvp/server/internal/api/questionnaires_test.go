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

// Questionnaires (issue #298): who manages them, that requests and role requests are refused
// without valid answers (whatever the client sends), what approvers see, what the audit event
// records, and that tenants do not see each other's.

const whyQuestions = `[
 {"type":"long_text","text":"Why do you need this?","required":true,"max_length":300},
 {"type":"single_choice","text":"Where will you use it?","options":["production","staging"],"required":true},
 {"type":"multi_choice","text":"Which tools?","options":["cli","ui","api"]},
 {"type":"yes_no","text":"Will you stop using it within the quarter?"},
 {"type":"date","text":"Needed until"},
 {"type":"short_text","text":"Ticket","max_length":20}]`

func TestQuestionnairesAPI_RequestsAndRoles(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	auditor := reqLogin(t, f, "au@b.example", []auth.Role{auth.RoleAuditor}, "")
	call := func(l authtest.Login, method, path, body string, want int) map[string]any {
		t.Helper()
		rec := reqDo(h, l, method, path, body)
		if rec.Code != want {
			t.Fatalf("%s %s: %d (want %d) %s", method, path, rec.Code, want, rec.Body)
		}
		if strings.HasPrefix(rec.Body.String(), "{") {
			return jsonMap(t, rec.Body.String())
		}
		return nil
	}

	// only catalog.manage holders manage questionnaires; the body is validated
	call(alice, "GET", "/api/questionnaires", "", 403)
	call(alice, "POST", "/api/questionnaires", `{"title":"x","questions":[{"type":"yes_no","text":"x"}]}`, 403)
	call(auditor, "POST", "/api/questionnaires", `{"title":"x","questions":[{"type":"yes_no","text":"x"}]}`, 403)
	call(admin, "POST", "/api/questionnaires", `{"title":"x","questions":[]}`, 422)
	call(admin, "POST", "/api/questionnaires", `{"title":"x","questions":[{"type":"rating","text":"x"}]}`, 422)
	call(admin, "POST", "/api/questionnaires", `{"title":"x","questions":[{"type":"yes_no","text":"x"}],"surprise":1}`, 422)
	created := call(admin, "POST", "/api/questionnaires", `{"title":"Why do you need this?","description":"Shown to approvers","questions":`+whyQuestions+`}`, 201)
	qid := created["id"].(string)
	if created["version"].(float64) != 1 || created["status"] != "active" || len(created["questions"].([]any)) != 6 {
		t.Fatalf("created: %v", created)
	}
	call(admin, "POST", "/api/questionnaires", `{"title":"why do you need this?","questions":[{"type":"yes_no","text":"x"}]}`, 409) // same title

	// the item to request, and the questionnaire attached to it
	call(admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", f.B.IDs["group:okta:platform"]), `{"requestable":true,"risk":"low"}`, 200)
	itemID := call(alice, "GET", "/api/catalog", "", 200)["items"].([]any)[0].(map[string]any)["id"].(string)
	attach := func(id, kind, target string, want int) {
		t.Helper()
		call(admin, "PUT", "/api/questionnaires/"+id+"/attachments", fmt.Sprintf(`{"targets":[{"kind":%q,"target_id":%q}]}`, kind, target), want)
	}
	attach(qid, "catalog_item", "00000000-0000-4000-8000-00000000dead", 404)
	attach(qid, "everything", "x", 422)
	attach(qid, "privileged", "x", 422)
	attach(qid, "catalog_item", itemID, 200)
	other := call(admin, "POST", "/api/questionnaires", `{"title":"Other","questions":[{"type":"yes_no","text":"x"}]}`, 201)["id"].(string)
	attach(other, "catalog_item", itemID, 409) // one questionnaire per target

	// the form reads what to ask
	need := call(alice, "GET", "/api/questionnaires/needed?catalog_item_ids="+itemID, "", 200)["questionnaires"].([]any)
	if len(need) != 1 || need[0].(map[string]any)["id"] != qid || need[0].(map[string]any)["version"].(float64) != 1 {
		t.Fatalf("needed: %v", need)
	}
	if got := call(alice, "GET", "/api/questionnaires/needed?catalog_item_ids=nope", "", 404); got == nil {
		t.Error("an unknown item was accepted")
	}

	// a request without valid answers is refused by the server
	submit := func(l authtest.Login, answers string, want int) map[string]any {
		t.Helper()
		extra := ""
		if answers != "" {
			extra = `,"answers":` + answers
		}
		return call(l, "POST", "/api/requests", fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":[%q],"justification":"for the Atlas project","duration_hours":8%s}`,
			f.B.IDs["alice"], itemID, extra), want)
	}
	qs := created["questions"].([]any)
	qID := func(i int) string { return qs[i].(map[string]any)["id"].(string) }
	ans := func(kv string) string { return fmt.Sprintf(`{%q:{%s}}`, qid, kv) }
	good := fmt.Sprintf(`%q:"Month-end close","%s":"production","%s":["api","cli"],"%s":true,"%s":"2026-12-31"`, qID(0), qID(1), qID(2), qID(3), qID(4))
	submit(alice, "", 422)
	for name, a := range map[string]string{
		"missing required": ans(fmt.Sprintf(`%q:"x"`, qID(0))),
		"choice outside":   ans(fmt.Sprintf(`%q:"x","%s":"dev"`, qID(0), qID(1))),
		"too long":         ans(fmt.Sprintf(`%q:%q,"%s":"staging"`, qID(0), strings.Repeat("w", 301), qID(1))),
		"bad date":         ans(fmt.Sprintf(`%q:"x","%s":"staging","%s":"soon"`, qID(0), qID(1), qID(4))),
		"unknown question": ans(fmt.Sprintf(`%q:"x","%s":"staging","nope":1`, qID(0), qID(1))),
		"other form":       fmt.Sprintf(`{%q:{"q1":true}}`, other),
	} {
		rec := reqDo(h, alice, "POST", "/api/requests", fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":[%q],"justification":"for the Atlas project","duration_hours":8,"answers":%s}`,
			f.B.IDs["alice"], itemID, a))
		if rec.Code != 422 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	ok := submit(alice, ans(good), 201)
	lineID := ok["lines"].([]any)[0].(map[string]any)["id"].(string)

	// approvers see the answers beside the questions, with the version they were given against
	line := call(admin, "GET", "/api/requests/"+lineID, "", 200)
	qa := line["questionnaires"].([]any)
	if len(qa) != 1 {
		t.Fatalf("line answers: %v", line["questionnaires"])
	}
	a0 := qa[0].(map[string]any)
	items := a0["items"].([]any)
	if a0["version"].(float64) != 1 || a0["title"] != "Why do you need this?" || len(items) != 5 || a0["answered_by"] == "" ||
		items[0].(map[string]any)["text"] != "Why do you need this?" || items[0].(map[string]any)["answer"] != "Month-end close" {
		t.Errorf("approver view: %v", a0)
	}
	hash := a0["answers_hash"].(string)
	if len(hash) != 64 {
		t.Errorf("hash: %q", hash)
	}
	// the submit event records the questionnaire, its version and the answers' hash, not the answers
	ev := qAuditDetail(t, f, "request.submit")
	rec, _ := json.Marshal(ev["questionnaires"])
	if !strings.Contains(string(rec), hash) || !strings.Contains(string(rec), `"version":1`) || strings.Contains(string(rec), "Month-end") {
		t.Errorf("audit detail: %s", rec)
	}

	// editing appends a version; the answered line keeps pointing at the version it was given against
	detail := call(admin, "GET", "/api/questionnaires/"+qid, "", 200)
	edited := call(admin, "PUT", "/api/questionnaires/"+qid, fmt.Sprintf(`{"version":1,"title":"Why do you need this?","description":"v2","questions":%s}`,
		strings.Replace(whyQuestions, `"text":"Ticket","max_length":20`, `"text":"Ticket","max_length":20,"required":true`, 1)), 200)
	if edited["version"].(float64) != 2 || len(edited["versions"].([]any)) != 2 || len(detail["versions"].([]any)) != 1 {
		t.Errorf("edit: %v", edited)
	}
	call(admin, "PUT", "/api/questionnaires/"+qid, `{"version":1,"title":"Why do you need this?","questions":[{"type":"yes_no","text":"x"}]}`, 409) // stale
	call(auditor, "PUT", "/api/questionnaires/"+qid, `{"version":2,"title":"t","questions":[{"type":"yes_no","text":"x"}]}`, 403)
	again := call(admin, "GET", "/api/requests/"+lineID, "", 200)["questionnaires"].([]any)[0].(map[string]any)
	if again["version"].(float64) != 1 || again["answers_hash"] != hash {
		t.Errorf("answered line moved to another version: %v", again)
	}
	// the new version has a new required question: the old answers no longer pass
	call(admin, "POST", "/api/requests/"+lineID+"/approve", `{}`, 200)
	call(alice, "POST", "/api/requests/"+lineID+"/remove", `{}`, 200)
	submit(alice, ans(good), 422)
	ok = submit(alice, ans(good+fmt.Sprintf(`,"%s":"SEC-9"`, qID(5))), 201)
	line2 := call(admin, "GET", "/api/requests/"+ok["lines"].([]any)[0].(map[string]any)["id"].(string), "", 200)
	if v := line2["questionnaires"].([]any)[0].(map[string]any)["version"].(float64); v != 2 {
		t.Errorf("the new request was answered against version %v", v)
	}

	// privileged items and high-risk roles ask the privileged questionnaire
	priv := call(admin, "POST", "/api/questionnaires", `{"title":"Privileged risk","questions":[{"id":"owner","type":"short_text","text":"Who owns the risk?","required":true}]}`, 201)["id"].(string)
	attach(priv, "privileged", "*", 200)
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.UpsertGroup(&store.Group{TenantID: f.B.ID, System: "okta", ExternalID: "vault-admins", Name: "vault-admins", Kind: "group", Privileged: true, Requestable: true})
	}); err != nil {
		t.Fatal(err)
	}
	var vault int64
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		g, err := c.GroupByXID("okta", "vault-admins")
		if g != nil {
			vault = g.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	vaultItem := call(admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", vault), `{"requestable":true,"risk":"high","default_hours":8}`, 200)["id"].(string)
	need = call(alice, "GET", "/api/questionnaires/needed?catalog_item_ids="+vaultItem+","+itemID, "", 200)["questionnaires"].([]any)
	if len(need) != 2 {
		t.Fatalf("privileged cart should ask two questionnaires: %v", need)
	}
	vaultReq := func(answers string, want int) {
		t.Helper()
		call(alice, "POST", "/api/requests", fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":[%q],"justification":"break glass drill","answers":%s}`, f.B.IDs["alice"], vaultItem, answers), want)
	}
	vaultReq(`{}`, 422)
	vaultReq(fmt.Sprintf(`{%q:{"owner":"the CISO"}}`, qid), 422) // answers a form this item does not ask
	vaultReq(fmt.Sprintf(`{%q:{"owner":"the CISO"}}`, priv), 201)

	call(admin, "PUT", "/api/questionnaires/"+qid+"/attachments", `{"targets":[]}`, 200) // detach, keep the attachment for roles below
	role := call(admin, "POST", "/api/roles", fmt.Sprintf(`{"name":"Payments","risk":"high","requestable":true,"entitlement_group_ids":[%d]}`, f.B.IDs["group:okta:payments-clerks"]), 201)
	roleID := role["role"].(map[string]any)["id"].(string)
	roleReq := func(answers string, want int) map[string]any {
		t.Helper()
		return call(alice, "POST", "/api/role-requests", fmt.Sprintf(`{"role_id":%q,"justification":"month-end","answers":%s}`, roleID, answers), want)
	}
	roleReq(`{}`, 422)
	rr := roleReq(fmt.Sprintf(`{%q:{"owner":"Finance"}}`, priv), 201)
	if qa := rr["questionnaires"].([]any); len(qa) != 1 || qa[0].(map[string]any)["items"].([]any)[0].(map[string]any)["answer"] != "Finance" {
		t.Errorf("role request answers: %v", rr["questionnaires"])
	}
	if ev := qAuditDetail(t, f, "role.request.submit"); ev["questionnaires"] == nil {
		t.Errorf("role request audit detail: %v", ev)
	}

	// retiring stops it being asked; its answers stay
	retired := call(admin, "POST", "/api/questionnaires/"+priv+"/retire", `{}`, 200)
	if retired["status"] != "retired" || len(retired["targets"].([]any)) != 0 {
		t.Errorf("retire: %v", retired)
	}
	call(admin, "POST", "/api/questionnaires/"+priv+"/retire", `{}`, 409)
	call(admin, "PUT", "/api/questionnaires/"+priv, `{"version":1,"title":"x","questions":[{"type":"yes_no","text":"x"}]}`, 409)
	need = call(alice, "GET", "/api/questionnaires/needed?catalog_item_ids="+vaultItem, "", 200)["questionnaires"].([]any)
	if len(need) != 0 {
		t.Errorf("a retired questionnaire is still asked: %v", need)
	}
}

// qAuditDetail is the detail of the newest audit event of an action in tenant B.
func qAuditDetail(t *testing.T, f *storetest.Fixture, action string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{})
		for _, e := range evs { // newest first
			if e.Action == action {
				return json.Unmarshal(e.Detail, &out)
			}
		}
		return err
	}); err != nil || out == nil {
		t.Fatalf("no %s event: %v", action, err)
	}
	return out
}

// Questionnaires of one tenant are invisible to another.
func TestQuestionnairesAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	adminB := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	adminA := signInA(t, f, auth.RolePolicyAdmin)
	rec := reqDo(h, adminA, "POST", "/api/questionnaires", `{"title":"A only","questions":[{"type":"yes_no","text":"A secret question"}]}`)
	if rec.Code != 201 {
		t.Fatalf("create in A: %d %s", rec.Code, rec.Body)
	}
	idA := jsonMap(t, rec.Body.String())["id"].(string)
	if rec := reqDo(h, adminB, "GET", "/api/questionnaires", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), "A only") || strings.Contains(rec.Body.String(), idA) {
		t.Errorf("B lists A's: %d %s", rec.Code, rec.Body)
	}
	missing := reqDo(h, adminB, "GET", "/api/questionnaires/00000000-0000-4000-8000-00000000dead", "")
	for _, c := range []struct{ method, suffix, body string }{
		{"GET", "", ""}, {"PUT", "", `{"version":1,"title":"x","questions":[{"type":"yes_no","text":"x"}]}`},
		{"POST", "/retire", `{}`}, {"PUT", "/attachments", `{"targets":[{"kind":"privileged","target_id":"*"}]}`},
	} {
		cross := reqDo(h, adminB, c.method, "/api/questionnaires/"+idA+c.suffix, c.body)
		if cross.Code != 404 || strings.Contains(cross.Body.String(), "A only") || strings.Contains(cross.Body.String(), idA) {
			t.Errorf("%s %s: %d %s (missing: %d)", c.method, c.suffix, cross.Code, cross.Body, missing.Code)
		}
	}
	// B's own questionnaire with the same title is fine
	if rec := reqDo(h, adminB, "POST", "/api/questionnaires", `{"title":"A only","questions":[{"type":"yes_no","text":"x"}]}`); rec.Code != 201 {
		t.Errorf("same title in B: %d %s", rec.Code, rec.Body)
	}
}

// A review decision answers the campaign's questionnaire; the server validates it, the answers
// are stored with the decision, and the audit ledger carries their hash and the version.
func TestQuestionnairesAPI_ReviewDecision(t *testing.T) {
	c := newRD(t)
	var campaign int64
	c.read(func(tx *store.TenantTx) error {
		it, err := tx.Item(1)
		campaign = it.CampaignID
		return err
	})
	created := c.json("POST", "/api/questionnaires", `{"title":"Review","questions":[
		{"id":"basis","type":"single_choice","text":"Basis","options":["still needed","not needed"],"required":true},
		{"id":"note","type":"long_text","text":"Note"}]}`, 201)
	qid := created["id"].(string)
	c.json("PUT", "/api/questionnaires/"+qid+"/attachments", fmt.Sprintf(`{"targets":[{"kind":"review_campaign","target_id":"%d"}]}`, campaign), 200)

	need := c.json("GET", "/api/questionnaires/needed?review_item_id=1", "", 200)["questionnaires"].([]any)
	if len(need) != 1 {
		t.Fatalf("needed for the item: %v", need)
	}
	if byCampaign := c.json("GET", fmt.Sprintf("/api/questionnaires/needed?review_campaign_id=%d", campaign), "", 200)["questionnaires"].([]any); len(byCampaign) != 1 {
		t.Fatalf("needed for the campaign: %v", byCampaign)
	}
	c.json("GET", "/api/questionnaires/needed?review_campaign_id=999999", "", 404)
	// no answers, wrong answers: refused, and the item stays open
	c.json("POST", "/api/reviews/items/1/decision", `{"decision":"keep"}`, 422)
	c.json("POST", "/api/reviews/items/1/decision", `{"decision":"keep","answers":{"basis":"because"}}`, 422)
	c.json("POST", "/api/reviews/items/1/decision", `{"decision":"keep","answers":{"basis":"still needed","extra":1}}`, 422)
	if d, _ := itemState(c, 1); d != "" {
		t.Fatalf("a refused decision decided the item: %q", d)
	}
	c.json("POST", "/api/reviews/items/1/decision", `{"decision":"keep","answers":{"basis":"still needed","note":"owner confirmed"}}`, 200)
	var hash string
	c.read(func(tx *store.TenantTx) error {
		as, err := tx.QuestionnaireAnswersFor(store.QSubjectReviewItem, "1")
		if err != nil || len(as) != 1 || as[0].Version != 1 {
			t.Fatalf("stored answers: %v %v", as, err)
		}
		hash = as[0].Hash
		return nil
	})
	evs := reviewEvents(c, "review.answers")
	if len(evs) != 1 || !strings.Contains(string(evs[0].Detail), hash) || !strings.Contains(string(evs[0].Detail), `"version":1`) ||
		strings.Contains(string(evs[0].Detail), "owner confirmed") {
		t.Fatalf("answers audit event: %v", evs)
	}
	// repeating the decision is a no-op: it asks nothing and writes nothing
	c.json("POST", "/api/reviews/items/1/decision", `{"decision":"keep"}`, 200)
	if n := len(reviewEvents(c, "review.answers")); n != 1 {
		t.Errorf("a repeated decision wrote %d answer events", n)
	}
	// a campaign with no questionnaire takes no answers
	c.json("POST", "/api/questionnaires/"+qid+"/retire", `{}`, 200)
	c.json("POST", "/api/reviews/items/2/decision", `{"decision":"keep","answers":{"basis":"still needed"}}`, 422)
	c.json("POST", "/api/reviews/items/2/decision", `{"decision":"keep"}`, 200)
}
