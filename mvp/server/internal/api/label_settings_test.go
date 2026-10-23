package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Labels, language and the email-logo switch (Admin > Branding & labels): who may change them, what is refused, that
// every signed-in person and the public pages see them, and that another tenant does not.
func TestLabelSettingsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: now.Add(-20 * time.Minute)}, now)
	auditor := signIn(t, f.DB, f.B.ID, authtest.User{Email: "au@b.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	viewerA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)

	var v labelsView
	rec := reqDo(h, auditor, "GET", "/api/admin/labels", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 || v.Version != 0 || v.DefaultLanguage != "" || v.EmailLogo ||
		len(v.Labels) != 0 || len(v.Terms) == 0 || len(v.Languages) == 0 || v.CanManage {
		t.Fatalf("defaults: %d %s", rec.Code, rec.Body)
	}
	body := `{"version":0,"default_language":"de-DE","email_logo":true,"labels":{"entitlement":"permission set","group":"Team"}}`
	for who, l := range map[string]authtest.Login{"viewer": viewer, "auditor": auditor} {
		if rec := reqDo(h, l, "PUT", "/api/admin/labels", body); rec.Code != 403 {
			t.Errorf("%s PUT: %d", who, rec.Code)
		}
	}
	if rec := reqDo(h, stale, "PUT", "/api/admin/labels", body); rec.Code != 401 && rec.Code != 403 {
		t.Errorf("PUT without a fresh sign-in: %d", rec.Code)
	}
	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"unknown language": {`{"version":0,"default_language":"xx-XX","labels":{}}`, 422},
		"unknown term":     {`{"version":0,"labels":{"role":"job"}}`, 422},
		"markup":           {`{"version":0,"labels":{"group":"<img src=x>"}}`, 422},
		"long label":       {`{"version":0,"labels":{"group":"` + strings.Repeat("x", 41) + `"}}`, 422},
		"stale version":    {`{"version":3,"labels":{}}`, 409},
		"unknown field":    {`{"version":0,"labels":{},"theme":"dark"}`, 422},
	} {
		if rec := reqDo(h, admin, "PUT", "/api/admin/labels", tc.body); rec.Code != tc.code {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, tc.code)
		}
	}
	rec = reqDo(h, admin, "PUT", "/api/admin/labels", body)
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 || v.Version != 1 || v.DefaultLanguage != "de-DE" || !v.EmailLogo ||
		v.Labels["entitlement"] != "permission set" || !v.CanManage {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}

	// every signed-in person gets the tenant's defaults with their preferences
	var p struct {
		TenantLanguage string            `json:"tenant_language"`
		Labels         map[string]string `json:"labels"`
		Locale         string            `json:"locale"`
	}
	rec = reqDo(h, viewer, "GET", "/api/me/preferences", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || rec.Code != 200 || p.TenantLanguage != "de-DE" || p.Labels["group"] != "Team" || p.Locale != "" {
		t.Errorf("preferences: %d %s", rec.Code, rec.Body)
	}
	// the sign-in and claim pages know the language
	pub := serve(h, httptest.NewRequest("GET", "/api/auth/branding?tenant="+f.B.Slug, nil))
	var m map[string]any
	if err := json.Unmarshal(pub.Body.Bytes(), &m); err != nil || m["language"] != "de-DE" {
		t.Errorf("public branding: %d %s", pub.Code, pub.Body)
	}
	pub = serve(h, httptest.NewRequest("GET", "/api/auth/branding?tenant=no-such-tenant", nil))
	if err := json.Unmarshal(pub.Body.Bytes(), &m); err != nil || m["language"] != "" {
		t.Errorf("public branding of an unknown tenant: %d %s", pub.Code, pub.Body)
	}
	// another tenant keeps the defaults
	rec = reqDo(h, viewerA, "GET", "/api/me/preferences", "")
	p.TenantLanguage, p.Labels = "x", nil
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.TenantLanguage != "" || len(p.Labels) != 0 {
		t.Errorf("tenant A sees B's labels: %s", rec.Body)
	}
	// the change is audited
	if rec := reqDo(h, auditor, "GET", "/api/audit", ""); !strings.Contains(rec.Body.String(), "branding.labels.update") {
		t.Errorf("no branding.labels.update event: %.300s", rec.Body)
	}
}
