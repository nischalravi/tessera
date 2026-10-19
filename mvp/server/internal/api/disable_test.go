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
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type disableOut struct {
	Status  string `json:"status"`
	Disable struct {
		ID                string `json:"id"`
		ContainmentStatus string `json:"containment_status"`
		Accounts          []struct {
			System, Username string
		} `json:"accounts"`
		EnabledAt *string `json:"enabled_at"`
	} `json:"disable"`
	Containment struct {
		Status string `json:"status"`
	} `json:"containment"`
	Restored []struct{ Username string } `json:"restored"`
	Skipped  []struct{ Username string } `json:"skipped"`
	NotRest  string                      `json:"not_restored"`
}

func identityStatus(t *testing.T, h http.Handler, l authtest.Login, id int64) string {
	t.Helper()
	rec := corrDo(h, l, "GET", fmt.Sprintf("/api/identities/%d", id), "")
	var d struct {
		Status   string `json:"status"`
		Accounts []struct {
			Status string `json:"status"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || rec.Code != 200 {
		t.Fatalf("identity: %d %.300s", rec.Code, rec.Body)
	}
	return d.Status
}

func TestDisableEnableAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := containServer(t, f).Handler()
	okta := newFakeOkta(t)
	l := policyAdmin(t, f, f.A.ID, "pa@a.example")
	admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	setCredential(t, h, admin, f.A.Refs["connection"], okta.srv.URL)
	alice := f.A.IDs["alice"]
	disable := fmt.Sprintf("/api/identities/%d/disable", alice)
	enable := fmt.Sprintf("/api/identities/%d/enable", alice)
	const body = `{"reason":"suspected account takeover"}`

	// Enable before Disable has nothing to restore
	if rec := corrDo(h, l, "POST", enable, body); rec.Code != 409 {
		t.Errorf("enable of an enabled identity: %d %s", rec.Code, rec.Body)
	}

	// Disable runs the containment steps at the provider, then disables locally
	rec := corrDo(h, l, "POST", disable, body)
	var out disableOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 || out.Status != "disabled" ||
		out.Containment.Status != "done" || out.Disable.ContainmentStatus != "done" || len(out.Disable.Accounts) == 0 {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	if got := strings.Join(okta.Calls(), ","); !strings.Contains(got, "DELETE /api/v1/users/alice/sessions") {
		t.Errorf("provider calls %s", got)
	}
	if st := identityStatus(t, h, l, alice); st != "disabled" {
		t.Errorf("status after disable = %s", st)
	}
	got := auditActions(t, f, f.A.ID)
	if got["identity.disable"] != 1 || got["containment.run"] < 1 {
		t.Errorf("audit actions %v", got)
	}
	if rec := corrDo(h, l, "POST", disable, body); rec.Code != 409 {
		t.Errorf("second disable: %d %s", rec.Code, rec.Body)
	}

	// the record lists what Disable changed
	rec = corrDo(h, l, "GET", fmt.Sprintf("/api/identities/%d/disables", alice), "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), out.Disable.ID) || !strings.Contains(rec.Body.String(), `"enabled_at":null`) {
		t.Errorf("disables: %d %s", rec.Code, rec.Body)
	}

	// Enable restores the accounts Disable disabled and says what it cannot restore
	rec = corrDo(h, l, "POST", enable, body)
	var en disableOut
	if err := json.Unmarshal(rec.Body.Bytes(), &en); err != nil || rec.Code != 200 || en.Status != "active" ||
		len(en.Restored) != len(out.Disable.Accounts) || len(en.Skipped) != 0 || en.Disable.EnabledAt == nil ||
		!strings.Contains(en.NotRest, "stay revoked") {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}
	if st := identityStatus(t, h, l, alice); st != "active" {
		t.Errorf("status after enable = %s", st)
	}
	if got := auditActions(t, f, f.A.ID); got["identity.enable"] != 1 {
		t.Errorf("audit actions %v", got)
	}
	if rec := corrDo(h, l, "POST", enable, body); rec.Code != 409 {
		t.Errorf("second enable: %d %s", rec.Code, rec.Body)
	}
	// and the person can be disabled again
	if rec := corrDo(h, l, "POST", disable, body); rec.Code != 200 {
		t.Errorf("disable again: %d %s", rec.Code, rec.Body)
	}
}

func TestDisableAPI_FailedProviderStepStillDisables(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := containServer(t, f).Handler()
	okta := newFakeOkta(t)
	okta.keepToken = true
	l := policyAdmin(t, f, f.A.ID, "pa@a.example")
	admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	setCredential(t, h, admin, f.A.Refs["connection"], okta.srv.URL)
	rec := corrDo(h, l, "POST", fmt.Sprintf("/api/identities/%d/disable", f.A.IDs["alice"]), `{"reason":"suspected account takeover"}`)
	var out disableOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 || out.Containment.Status != "retrying" ||
		out.Disable.ContainmentStatus != "retrying" {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	if got := auditActions(t, f, f.A.ID); got["containment.retry_scheduled"] != 1 || got["identity.disable"] != 1 {
		t.Errorf("audit actions %v", got)
	}
}

func TestDisableEnableAPI_Access(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := containServer(t, f).Handler()
	l := policyAdmin(t, f, f.A.ID, "pa@a.example")
	lb := policyAdmin(t, f, f.B.ID, "pa@b.example")
	admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	viewer := signIn(t, f.DB, f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	stale := signIn(t, f.DB, f.A.ID, authtest.User{Email: "stale@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	alice := f.A.IDs["alice"]
	base := fmt.Sprintf("/api/identities/%d", alice)
	const body = `{"reason":"suspected account takeover"}`

	for name, tc := range map[string]struct {
		login      authtest.Login
		method     string
		path, body string
		want       int
	}{
		"no reason":             {l, "POST", base + "/disable", `{}`, 422},
		"short reason":          {l, "POST", base + "/disable", `{"reason":"x"}`, 422},
		"unknown field":         {l, "POST", base + "/disable", `{"reason":"suspected account takeover","x":1}`, 422},
		"unknown person":        {l, "POST", "/api/identities/999999/disable", body, 404},
		"enable unknown person": {l, "POST", "/api/identities/999999/enable", body, 404},
		"tenant admin disable":  {admin, "POST", base + "/disable", body, 403},
		"viewer disable":        {viewer, "POST", base + "/disable", body, 403},
		"viewer enable":         {viewer, "POST", base + "/enable", body, 403},
		"stale sign-in disable": {stale, "POST", base + "/disable", body, 401},
		"stale sign-in enable":  {stale, "POST", base + "/enable", body, 401},
		"other tenant disable":  {lb, "POST", base + "/disable", body, 404},
		"other tenant enable":   {lb, "POST", base + "/enable", body, 404},
		"other tenant list":     {lb, "GET", base + "/disables", "", 404},
		"viewer lists disables": {viewer, "GET", base + "/disables", "", 200},
	} {
		if rec := corrDo(h, tc.login, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, tc.want)
		}
	}
	if got := auditActions(t, f, f.A.ID); got["identity.disable"] != 0 {
		t.Errorf("a refused request disabled someone: %v", got)
	}
	// B disabling its own alice does not touch A's
	if rec := corrDo(h, lb, "POST", fmt.Sprintf("/api/identities/%d/disable", f.B.IDs["alice"]), body); rec.Code != 200 {
		t.Fatalf("B disable: %d %s", rec.Code, rec.Body)
	}
	if st := identityStatus(t, h, l, alice); st != "active" {
		t.Errorf("A's alice status = %s after B's disable", st)
	}
}
