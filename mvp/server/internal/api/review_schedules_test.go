package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func schedDo(h http.Handler, l authtest.Login, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	l.Apply(req)
	return serve(h, req)
}

func TestReviewSchedulesAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	op := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	first := storetest.Now.Add(24 * 3600e9).UTC().Format("2006-01-02T15:04:05Z")
	body := fmt.Sprintf(`{"name":"Quarterly privileged","privileged_only":true,"recurrence":"quarterly","first_run_at":"%s",
		"close_out":"escalate","escalation_identity_id":%d}`, first, f.B.IDs["carol"])
	if rec := schedDo(h, viewer, "POST", "/api/reviews/schedules", body); rec.Code != 403 {
		t.Errorf("viewer creates: %d", rec.Code)
	}
	rec := schedDo(h, op, "POST", "/api/reviews/schedules", body)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var v scheduleView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.EscalationReviewer == nil || v.NextRunAt == nil || v.DurationDays != 14 {
		t.Errorf("view %s", rec.Body)
	}
	bad := strings.Replace(body, `"quarterly"`, `"weekly"`, 1)
	if rec := schedDo(h, op, "POST", "/api/reviews/schedules", bad); rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_recurrence") {
		t.Errorf("bad recurrence: %d %s", rec.Code, rec.Body)
	}
	// update keeps the next run when none is given
	rec = schedDo(h, op, "PUT", "/api/reviews/schedules/"+v.ID, `{"name":"Quarterly privileged","privileged_only":true,"recurrence":"annual"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"recurrence":"annual"`) || !strings.Contains(rec.Body.String(), first) {
		t.Errorf("update: %d %s", rec.Code, rec.Body)
	}
	rec = schedDo(h, op, "POST", "/api/reviews/schedules/"+v.ID+"/run", "")
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"period":"manual-`) {
		t.Fatalf("run now: %d %s", rec.Code, rec.Body)
	}
	rec = schedDo(h, viewer, "GET", "/api/reviews/schedules", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"launches":[{`) {
		t.Errorf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := schedDo(h, viewer, "GET", "/api/reviews/campaigns", ""); !strings.Contains(rec.Body.String(), "Quarterly privileged · manual-") {
		t.Errorf("the launched campaign is not listed: %s", rec.Body)
	}
	acts := reviewAudit(t, f)
	if acts["review.schedule.put"] != 2 || acts["review.schedule.launch"] != 1 {
		t.Errorf("audit %v", acts)
	}
}

func TestReviewSchedulesAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	opA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "op@a.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	opB := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	rec := schedDo(h, opA, "POST", "/api/reviews/schedules", `{"name":"A's","recurrence":"once","first_run_at":"2030-01-01T00:00:00Z"}`)
	if rec.Code != 201 {
		t.Fatalf("A creates: %d %s", rec.Code, rec.Body)
	}
	var v scheduleView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	before := storetest.Dump(t, f.DB, f.A.ID)
	for _, c := range []struct{ method, suffix, body string }{
		{"PUT", "", `{"name":"x","recurrence":"once","first_run_at":"2030-01-01T00:00:00Z"}`}, {"POST", "/run", ""},
	} {
		cross := schedDo(h, opB, c.method, "/api/reviews/schedules/"+v.ID+c.suffix, c.body)
		missing := schedDo(h, opB, c.method, "/api/reviews/schedules/00000000-0000-4000-8000-00000000dead"+c.suffix, c.body)
		if cross.Code != 404 || cross.Body.String() != missing.Body.String() {
			t.Errorf("%s %s: %d %s", c.method, c.suffix, cross.Code, cross.Body)
		}
	}
	if rec := schedDo(h, opB, "GET", "/api/reviews/schedules", ""); strings.Contains(rec.Body.String(), v.ID) {
		t.Error("B lists A's schedule")
	}
	// B naming A's identity as the escalation reviewer: as for a missing one
	rec = schedDo(h, opB, "POST", "/api/reviews/schedules", fmt.Sprintf(`{"name":"x","recurrence":"once","first_run_at":"2030-01-01T00:00:00Z","close_out":"escalate","escalation_identity_id":%d}`, f.A.IDs["carol"]))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "escalation_reviewer_not_found") {
		t.Errorf("A's reviewer: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("B changed tenant A")
	}
}

func reviewAudit(t *testing.T, f *storetest.Fixture) map[string]int {
	t.Helper()
	out := map[string]int{}
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			out[e.Action]++
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// #318 and #317: an unknown system is refused at create and update, and a
// second manual run in the same second is a clean 409.
func TestReviewSchedulesAPI_SystemAndDoubleRun(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	op := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	mk := func(system string) string {
		return `{"name":"x","recurrence":"once","system":"` + system + `","first_run_at":"2030-01-01T00:00:00Z"}`
	}
	for _, c := range []struct {
		system string
		code   int
	}{{"nosuchsystem", 422}, {"AWS", 422}, {"aws", 201}} {
		rec := schedDo(h, op, "POST", "/api/reviews/schedules", mk(c.system))
		if rec.Code != c.code || (c.code == 422 && !strings.Contains(rec.Body.String(), "invalid_system")) {
			t.Errorf("create system %q: %d %s", c.system, rec.Code, rec.Body)
		}
	}
	rec := schedDo(h, op, "POST", "/api/reviews/schedules", mk("aws"))
	var v scheduleView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if rec := schedDo(h, op, "PUT", "/api/reviews/schedules/"+v.ID, mk("awss")); rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_system") {
		t.Errorf("update to an unknown system: %d %s", rec.Code, rec.Body)
	}
	first := schedDo(h, op, "POST", "/api/reviews/schedules/"+v.ID+"/run", "")
	second := schedDo(h, op, "POST", "/api/reviews/schedules/"+v.ID+"/run", "")
	if first.Code != 201 || second.Code != 409 || !strings.Contains(second.Body.String(), "already_launched") {
		t.Errorf("run twice: %d then %d %s", first.Code, second.Code, second.Body)
	}
}
