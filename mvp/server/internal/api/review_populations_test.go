package api

import (
	"encoding/csv"
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

// Frozen review populations and the auditor export (issue #110).

func auditCount(t *testing.T, f *storetest.Fixture, action string) int {
	t.Helper()
	n := 0
	if err := f.DB.ReadTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: action})
		n = len(evs)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestReviewPopulationAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(t, f, f.B.ID).Handler()

	rec := serveOnce(h, "POST", "/api/reviews/campaigns", `{"name":"Q1 review"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	base := fmt.Sprintf("/api/reviews/campaigns/%d", created.ID)
	if n := auditCount(t, f, "review.population_frozen"); n != 1 {
		t.Errorf("%d review.population_frozen events after one launch, want 1", n)
	}
	// the campaign response is unchanged: the population has its own routes
	if strings.Contains(rec.Body.String(), "population") {
		t.Errorf("campaign response carries population fields: %s", rec.Body.String())
	}

	// summary
	rec = serveOnce(h, "GET", base+"/population", "")
	var pop struct {
		Hash   string         `json:"population_hash"`
		Match  bool           `json:"hash_match"`
		Items  int            `json:"item_count"`
		Counts map[string]int `json:"system_counts"`
		FrozAt string         `json:"frozen_at"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &pop) != nil || pop.Hash == "" || !pop.Match || pop.Items == 0 ||
		len(pop.Counts) == 0 || pop.FrozAt == "" {
		t.Fatalf("population: %d %s", rec.Code, rec.Body.String())
	}

	// JSON export, audited
	before := auditCount(t, f, "review.population_exported")
	rec = serveOnce(h, "GET", base+"/export?format=json", "")
	var ex struct {
		Population struct {
			Stored string           `json:"stored_hash"`
			Re     string           `json:"recomputed_hash"`
			Match  bool             `json:"hash_match"`
			Rows   []map[string]any `json:"rows"`
		} `json:"population"`
		Decisions []map[string]any `json:"decisions"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &ex) != nil {
		t.Fatalf("export json: %d %.300s", rec.Code, rec.Body.String())
	}
	if ex.Population.Stored != pop.Hash || ex.Population.Re != pop.Hash || !ex.Population.Match ||
		len(ex.Population.Rows) != pop.Items || len(ex.Decisions) != pop.Items {
		t.Errorf("export does not reproduce the hash: %+v", ex.Population)
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Errorf("Content-Disposition %q", rec.Header().Get("Content-Disposition"))
	}
	if auditCount(t, f, "review.population_exported") != before+1 {
		t.Error("the JSON export was not audited")
	}
	if leaks(rec.Body.String()) {
		t.Error("export leaks tenant A data")
	}

	// CSV export, audited, and the default format is JSON
	rec = serveOnce(h, "GET", base+"/export?format=csv", "")
	recs, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if rec.Code != 200 || err != nil || len(recs) != pop.Items+1 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export csv: %d %v %q", rec.Code, err, rec.Header().Get("Content-Type"))
	}
	if auditCount(t, f, "review.population_exported") != before+2 {
		t.Error("the CSV export was not audited")
	}
	if rec = serveOnce(h, "GET", base+"/export", ""); rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Errorf("default export: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}

	// refusals write no export event
	n := auditCount(t, f, "review.population_exported")
	for path, want := range map[string]int{base + "/export?format=xml": 422, "/api/reviews/campaigns/999999/export": 404,
		"/api/reviews/campaigns/999999/population": 404, "/api/reviews/campaigns/abc/export": 422} {
		if rec := serveOnce(h, "GET", path, ""); rec.Code != want {
			t.Errorf("GET %s: %d %.200s, want %d", path, rec.Code, rec.Body.String(), want)
		}
	}
	// a campaign launched before populations were frozen
	var legacy int64
	if err := f.DB.InTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		var err error
		legacy, err = c.InsertCampaign(&store.ReviewCampaign{Name: "legacy", CreatedAt: storetest.Now, Status: "open"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rec := serveOnce(h, "GET", fmt.Sprintf("/api/reviews/campaigns/%d/export", legacy), ""); rec.Code != 404 ||
		!strings.Contains(rec.Body.String(), "no frozen population") {
		t.Errorf("legacy export: %d %s", rec.Code, rec.Body.String())
	}
	if auditCount(t, f, "review.population_exported") != n {
		t.Error("a refused export was audited as an export")
	}
}

func TestReviewPopulationRoles(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	path := fmt.Sprintf("/api/reviews/campaigns/%d/export", f.B.IDs["campaign"])
	for role, want := range map[auth.Role]int{auth.RoleViewer: 403, auth.RoleTenantAdmin: 403, auth.RoleAuditor: 200,
		auth.RoleOperator: 200, auth.RolePolicyAdmin: 200} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		if rec := serve(h, authed(l, "GET", path, "")); rec.Code != want {
			t.Errorf("%s export: %d %.200s, want %d", role, rec.Code, rec.Body.String(), want)
		}
	}
	// the auditor reads but cannot change the sample or decide
	aud := signIn(t, f.DB, f.B.ID, authtest.User{Email: "aud2@b.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, storetest.Now)
	for _, c := range [][3]string{{"PUT", "/api/reviews/settings", `{"qa_sample_pct":50}`},
		{"POST", fmt.Sprintf("/api/reviews/qa/%d/decision", f.B.IDs["qa"]), `{"decision":"revoke"}`}} {
		if rec := serve(h, authed(aud, c[0], c[1], c[2])); rec.Code != 403 {
			t.Errorf("auditor %s %s: %d, want 403", c[0], c[1], rec.Code)
		}
	}
	if rec := serve(h, authed(aud, "GET", fmt.Sprintf("/api/reviews/campaigns/%d/population", f.B.IDs["campaign"]), "")); rec.Code != 200 {
		t.Errorf("auditor population: %d", rec.Code)
	}
}

func TestReviewQAAndSettingsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := asLinkedAdmin(t, newIsolationServer(f), f.DB, f.B.ID, storetest.Now).Handler()
	for body, want := range map[string]int{`{"qa_sample_pct":101}`: 400, `{"qa_sample_pct":-1}`: 400, `{"qa_sample_pct":"x"}`: 422,
		`{}`: 422, `{"qa_sample_pct":25}`: 200} {
		if rec := serveOnce(h, "PUT", "/api/reviews/settings", body); rec.Code != want {
			t.Errorf("PUT settings %s: %d %.200s, want %d", body, rec.Code, rec.Body.String(), want)
		}
	}
	if err := f.DB.ReadTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		if v, ok, _ := c.TenantSetting("qa_sample_pct"); !ok || v != "25" {
			t.Errorf("stored setting %q %v", v, ok)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := auditCount(t, f, "review.qa_sample_pct_changed"); n != 1 {
		t.Errorf("%d setting-change events, want 1", n)
	}

	qa := fmt.Sprintf("/api/reviews/qa/%d/decision", f.B.IDs["qa"])
	for body, want := range map[string]int{`{"decision":"maybe"}`: 422, `{}`: 422} {
		if rec := serveOnce(h, "POST", qa, body); rec.Code != want {
			t.Errorf("POST %s %s: %d, want %d", qa, body, rec.Code, want)
		}
	}
	rec := serveOnce(h, "POST", qa, `{"decision":"revoke","comment":"leaver still holds it"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"overturned":true`) {
		t.Fatalf("overturn: %d %s", rec.Code, rec.Body.String())
	}
	if n := auditCount(t, f, "review.qa_overturned"); n != 1 {
		t.Errorf("%d review.qa_overturned events, want 1", n)
	}
	if rec := serveOnce(h, "POST", qa, `{"decision":"keep"}`); rec.Code != 400 {
		t.Errorf("second QA decision: %d, want 400", rec.Code)
	}
	// the QA decision is in the export
	rec = serveOnce(h, "GET", fmt.Sprintf("/api/reviews/campaigns/%d/export", f.B.IDs["campaign"]), "")
	if !strings.Contains(rec.Body.String(), `"qa_decision":"revoke"`) {
		t.Errorf("export lacks the QA decision: %.400s", rec.Body.String())
	}
	// a QA decision is an attestation: it needs the same fresh sign-in as a review decision
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := serve(newIsolationServer(f).Handler(), authed(stale, "POST", qa, `{"decision":"keep"}`)); rec.Code != 401 ||
		!strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %.200s, want 401 step_up_required", rec.Code, rec.Body.String())
	}
}
