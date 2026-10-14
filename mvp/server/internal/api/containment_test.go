package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// fakeOkta is a small stateful Okta: it records the calls it gets and can be
// told to keep a refresh token alive after the revoke.
type fakeOkta struct {
	srv       *httptest.Server
	mu        sync.Mutex
	calls     []string
	keepToken bool
}

func newFakeOkta(t *testing.T) *fakeOkta {
	f := &fakeOkta{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "SSWS tok-api-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE":
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/clients") && f.keepToken:
			_, _ = io.WriteString(w, `[{"client_id":"0oaC1"}]`)
		case strings.HasSuffix(r.URL.Path, "/tokens"):
			_, _ = io.WriteString(w, `[{"id":"oar1"}]`)
		default:
			_, _ = io.WriteString(w, `[]`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOkta) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func containServer(t *testing.T, f *storetest.Fixture) *Server {
	t.Helper()
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{
		Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Containment: &containment.Service{HTTP: hc, Sealer: sealer, Sleep: func(context.Context, time.Duration) error { return nil }},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Env:         "test", RateLimits: noRateLimits, AllowedOrigins: []string{"http://localhost:5173"},
	})
}

type containReport struct {
	OK        bool                          `json:"ok"`
	Trigger   string                        `json:"trigger"`
	Steps     []containment.StepResult      `json:"steps"`
	Providers []containment.ProviderOutcome `json:"providers"`
	Manual    []containment.ManualTask      `json:"manual_tasks"`
}

func setCredential(t *testing.T, h http.Handler, l authtest.Login, conn, base string) {
	t.Helper()
	rec := corrDo(h, l, "PUT", "/api/connections/"+conn+"/containment-credential",
		fmt.Sprintf(`{"token":"tok-api-secret","base_url":%q}`, base))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "tok-api-secret") {
		t.Fatalf("credential: %d %s", rec.Code, rec.Body)
	}
}

// runEvents returns the containment.run events of a tenant, newest first.
func runEvents(t *testing.T, f *storetest.Fixture, tenant storetest.Tenant) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := f.DB.ReadTenant(context.Background(), tenant.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: "containment.run"})
		for _, e := range evs {
			var d map[string]any
			if err := json.Unmarshal(e.Detail, &d); err != nil {
				return err
			}
			out = append(out, d)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestContainAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := containServer(t, f).Handler()
	okta := newFakeOkta(t)
	l := policyAdmin(t, f, f.A.ID, "pa@a.example")
	admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	alice := fmt.Sprintf("/api/identities/%d/contain", f.A.IDs["alice"])
	const body = `{"reason":"suspected token theft"}`

	// without a credential the okta steps are manual tasks: the call succeeds, nothing is claimed done
	rec := corrDo(h, l, "POST", alice, body)
	var rep containReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil || rec.Code != 200 || !rep.OK || len(rep.Steps) != 2 {
		t.Fatalf("manual run: %d %s", rec.Code, rec.Body)
	}
	for _, st := range rep.Steps {
		if st.Outcome != containment.OutcomeManual || st.Verified {
			t.Errorf("step without a credential: %+v", st)
		}
	}
	if len(rep.Manual) != 2 || len(okta.Calls()) != 0 {
		t.Errorf("manual tasks %v, provider calls %v", rep.Manual, okta.Calls())
	}

	// with a credential the provider is called and re-read
	setCredential(t, h, admin, f.A.Refs["connection"], okta.srv.URL)
	rec = corrDo(h, l, "POST", alice, body)
	rep = containReport{}
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil || rec.Code != 200 || !rep.OK {
		t.Fatalf("run: %d %s", rec.Code, rec.Body)
	}
	for _, st := range rep.Steps {
		if st.Outcome != containment.OutcomeDone || !st.Verified {
			t.Errorf("step: %+v", st)
		}
	}
	if got := strings.Join(okta.Calls(), ","); !strings.Contains(got, "DELETE /api/v1/users/alice/sessions") {
		t.Errorf("provider calls %s", got)
	}
	evs := runEvents(t, f, f.A)
	if len(evs) != 2 || evs[0]["ok"] != true || evs[0]["trigger"] != "manual" || evs[0]["duration_ms"] == nil ||
		evs[0]["started_at"] == nil || evs[0]["providers"] == nil {
		t.Errorf("audit events %v", evs)
	}
	if len(runEvents(t, f, f.B)) != 0 {
		t.Error("tenant B's ledger holds tenant A's containment")
	}

	// a refresh token that survives the revoke fails the request, and the failure is recorded
	okta.keepToken = true
	rec = corrDo(h, l, "POST", alice, body)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"containment_failed"`) ||
		!strings.Contains(rec.Body.String(), "still found 1 active session") {
		t.Errorf("surviving token: %d %s", rec.Code, rec.Body)
	}
	if evs = runEvents(t, f, f.A); len(evs) != 3 || evs[0]["ok"] != false {
		t.Errorf("a failed run must be audited: %v", evs)
	}

	// input and permission checks
	for name, tc := range map[string]struct {
		login      authtest.Login
		path, body string
		want       int
	}{
		"no reason":      {l, alice, `{}`, 422},
		"short reason":   {l, alice, `{"reason":"x"}`, 422},
		"unknown field":  {l, alice, `{"reason":"suspected token theft","x":1}`, 422},
		"unknown person": {l, "/api/identities/999999/contain", body, 404},
		"tenant admin":   {admin, alice, body, 403}, // no identities.contain
	} {
		if rec := corrDo(h, tc.login, "POST", tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, tc.want)
		}
	}
	// the credential route validates its input (a GitHub org, an https URL)
	if rec := corrDo(h, admin, "PUT", "/api/connections/"+f.A.Refs["connection"]+"/containment-credential",
		`{"token":"t"}`); rec.Code != 422 {
		t.Errorf("okta without base_url: %d %s", rec.Code, rec.Body)
	}
}

func TestLeaverExecuteRunsContainment(t *testing.T) {
	leaver := func(f *storetest.Fixture) string {
		return fmt.Sprintf("/api/hris/events/%d/execute", f.A.IDs["hris:leaver"])
	}

	t.Run("a surviving token blocks the leaver", func(t *testing.T) {
		f := storetest.TwoTenants(t)
		h := containServer(t, f).Handler()
		okta := newFakeOkta(t)
		okta.keepToken = true
		l := policyAdmin(t, f, f.A.ID, "pa@a.example")
		admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
		setCredential(t, h, admin, f.A.Refs["connection"], okta.srv.URL)
		rec := corrDo(h, l, "POST", leaver(f), "")
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "containment_failed") {
			t.Fatalf("execute: %d %s", rec.Code, rec.Body)
		}
		evs := runEvents(t, f, f.A)
		if len(evs) != 1 || evs[0]["ok"] != false || evs[0]["trigger"] != "leaver" {
			t.Errorf("audit %v", evs)
		}
		// nothing was executed: the event is still pending, the accounts still active
		rec = corrDo(h, l, "GET", "/api/hris/events", "")
		if !strings.Contains(rec.Body.String(), `"status":"pending"`) || strings.Contains(rec.Body.String(), `"executed_at":"`) {
			t.Errorf("events: %.400s", rec.Body)
		}
		if got := auditActions(t, f, f.A.ID); got["jml.leaver"] != 0 {
			t.Errorf("the leaver was recorded as executed: %v", got)
		}
	})

	t.Run("with a credential the leaver executes after containment", func(t *testing.T) {
		f := storetest.TwoTenants(t)
		h := containServer(t, f).Handler()
		okta := newFakeOkta(t)
		l := policyAdmin(t, f, f.A.ID, "pa@a.example")
		admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
		setCredential(t, h, admin, f.A.Refs["connection"], okta.srv.URL)
		rec := corrDo(h, l, "GET", fmt.Sprintf("/api/hris/events/%d/plan", f.A.IDs["hris:leaver"]), "")
		if !strings.Contains(rec.Body.String(), `"action":"revoke_sessions"`) || !strings.Contains(rec.Body.String(), `"action":"revoke_grants"`) {
			t.Fatalf("plan lacks the containment steps: %.600s", rec.Body)
		}
		rec = corrDo(h, l, "POST", leaver(f), "")
		var out struct {
			Executed    bool          `json:"executed"`
			Containment containReport `json:"containment"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 || !out.Executed || !out.Containment.OK ||
			len(out.Containment.Steps) != 2 || out.Containment.Trigger != "leaver" {
			t.Fatalf("execute: %d %s", rec.Code, rec.Body)
		}
		got := auditActions(t, f, f.A.ID)
		if got["containment.run"] != 1 || got["jml.leaver"] != 1 {
			t.Errorf("audit %v", got)
		}
		if rec = corrDo(h, l, "POST", leaver(f), ""); rec.Code != 400 {
			t.Errorf("second execute: %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("without a credential the steps are manual tasks and the leaver still executes", func(t *testing.T) {
		f := storetest.TwoTenants(t)
		h := containServer(t, f).Handler()
		l := policyAdmin(t, f, f.A.ID, "pa@a.example")
		rec := corrDo(h, l, "POST", leaver(f), "")
		var out struct {
			Executed    bool          `json:"executed"`
			Containment containReport `json:"containment"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 || !out.Executed ||
			len(out.Containment.Manual) != 2 || out.Containment.Steps[0].Outcome != containment.OutcomeManual {
			t.Fatalf("execute: %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("a tenant without a connection gets no containment steps", func(t *testing.T) {
		f := storetest.TwoTenants(t)
		h := containServer(t, f).Handler()
		l := policyAdmin(t, f, f.B.ID, "pa@b.example")
		// B's connection is retired: the plan carries no steps for its okta account
		admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
		if rec := corrDo(h, admin, "POST", "/api/connections/"+f.B.Refs["connection"]+"/retire", `{"confirm":true}`); rec.Code != 200 {
			t.Skipf("cannot retire the fixture connection: %d %s", rec.Code, rec.Body)
		}
		rec := corrDo(h, l, "GET", fmt.Sprintf("/api/hris/events/%d/plan", f.B.IDs["hris:leaver"]), "")
		if strings.Contains(rec.Body.String(), "revoke_sessions") {
			t.Errorf("plan has containment steps without a live connection: %.600s", rec.Body)
		}
	})
}
