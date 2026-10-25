package api

import (
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TESSERA_STEPUP_BYPASS counts the step-up requirement as met for a signed-in
// session and nothing else: permissions still apply, and the audit trail marks
// the requests that would have needed step-up.
func TestStepUpBypass(t *testing.T) {
	now := storetest.Now
	const path = "/api/admin/branding"
	body := jsonStr(map[string]any{"display_name": "Larkspur Health", "primary_color": "#0F6CBD",
		"logo": logoJSON(testPNG(t, 96, 64), "image/png")})
	for _, tc := range []struct {
		name   string
		bypass bool
		env    string
		who    string // stale | fresh | viewer
		status int
		marked bool
	}{
		{"off, old sign-in: step-up required", false, "test", "stale", 401, false},
		{"on, old sign-in: step-up met", true, "test", "stale", 200, true},
		{"on, fresh sign-in: nothing to bypass", true, "test", "fresh", 200, false},
		{"off, fresh sign-in", false, "test", "fresh", 200, false},
		{"on, viewer: permissions still enforced", true, "test", "viewer", 403, false},
		{"on in prod: ignored at the use site", true, "prod", "stale", 401, false},
		{"on, Env unset: ignored (allow-list)", true, "", "stale", 401, false},
		{"on, Env Prod: ignored (allow-list)", true, "Prod", "stale", 401, false},
		{"on, Env with whitespace: ignored", true, " prod", "stale", 401, false},
		{"on, unknown Env: ignored", true, "staging", "stale", 401, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := storetest.TwoTenants(t)
			h := newIsolationServerWith(f, func(c *Config) { c.StepUpBypass, c.Env = tc.bypass, tc.env }).Handler()
			users := map[string]authtest.Login{
				"stale": signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
					authtest.Ctx{AAL: 2, Phr: true, AuthTime: now.Add(-20 * time.Minute)}, now),
				"fresh":  signIn(t, f.DB, f.B.ID, authtest.User{Email: "fresh@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now),
				"viewer": signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now),
			}
			rec := reqDo(h, users[tc.who], "PUT", path, body)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %.200s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.status == 401 && !strings.Contains(rec.Body.String(), "step_up_required") {
				t.Errorf("body %.200s, want step_up_required", rec.Body.String())
			}
			evs := httpEvents(ledger(t, f.DB, f.B.ID))
			last := evs[0] // newest first
			if got := strings.Contains(string(last.Detail), `"step_up_bypassed":true`); got != tc.marked {
				t.Errorf("audit marker %v, want %v (detail %s)", got, tc.marked, last.Detail)
			}
		})
	}
}

// The session payload tells the UI whether step-up is off.
func TestStepUpBypass_SessionFlag(t *testing.T) {
	for _, on := range []bool{false, true} {
		f := storetest.TwoTenants(t)
		h := newIsolationServerWith(f, func(c *Config) { c.StepUpBypass = on }).Handler()
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
		rec := reqDo(h, l, "GET", "/api/auth/session", "")
		want := `"step_up_bypass":false`
		if on {
			want = `"step_up_bypass":true`
		}
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("bypass=%v: %d %.300s, want %s", on, rec.Code, rec.Body.String(), want)
		}
	}
}
