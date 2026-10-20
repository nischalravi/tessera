package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func testPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	m := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			m.Set(x, y, color.RGBA{10, uint8(x), uint8(y), 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func logoJSON(data []byte, ct string) map[string]string {
	return map[string]string{"content_type": ct, "data_base64": base64.StdEncoding.EncodeToString(data)}
}

func TestBrandingAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: now.Add(-20 * time.Minute)}, now)
	auditor := signIn(t, f.DB, f.B.ID, authtest.User{Email: "au@b.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)

	// nothing saved: the defaults, for the admin and for the public pages (and for a tenant that does not exist)
	var v brandingView
	rec := reqDo(h, admin, "GET", "/api/admin/branding", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 || v.Configured || v.DisplayName != "Tessera" || v.Logo != nil {
		t.Fatalf("defaults: %d %s", rec.Code, rec.Body)
	}
	pub := func(q string) (int, map[string]any) {
		rec := serve(h, httptest.NewRequest("GET", "/api/auth/branding?tenant="+q, nil))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	if code, m := pub(f.B.Slug); code != 200 || m["name"] != "Tessera" || m["configured"] != false || m["logo_url"] != nil {
		t.Errorf("public default: %d %v", code, m)
	}
	if code, m := pub("no-such-tenant"); code != 200 || m["name"] != "Tessera" {
		t.Errorf("public unknown tenant: %d %v", code, m)
	}

	// who may change it
	logo := testPNG(t, 96, 64)
	body := jsonStr(map[string]any{"display_name": "Larkspur Health", "primary_color": "#0F6CBD", "logo": logoJSON(logo, "image/png")})
	if rec := reqDo(h, viewer, "PUT", "/api/admin/branding", body); rec.Code != 403 {
		t.Errorf("viewer PUT: %d", rec.Code)
	}
	if rec := reqDo(h, auditor, "PUT", "/api/admin/branding", body); rec.Code != 403 {
		t.Errorf("auditor PUT: %d", rec.Code)
	}
	if rec := reqDo(h, auditor, "GET", "/api/admin/branding", ""); rec.Code != 200 {
		t.Errorf("auditor GET: %d", rec.Code)
	}
	if rec := reqDo(h, viewer, "GET", "/api/admin/branding", ""); rec.Code != 403 {
		t.Errorf("viewer GET: %d", rec.Code)
	}
	if rec := reqDo(h, stale, "PUT", "/api/admin/branding", body); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale PUT: %d %s", rec.Code, rec.Body)
	}

	// refused input
	big := append(testPNG(t, 64, 64), bytes.Repeat([]byte{0}, 300<<10)...)
	for _, tc := range []struct {
		name string
		body map[string]any
		code int
		text string
	}{
		{"low contrast pair", map[string]any{"display_name": "X", "primary_color": "#ffe08a", "on_primary_color": "#ffffff"}, 422, "low_contrast"},
		{"bad colour", map[string]any{"display_name": "X", "primary_color": "red"}, 422, "invalid_color"},
		{"bad name", map[string]any{"display_name": "<b>x</b>", "primary_color": "#0f6cbd"}, 422, "invalid_name"},
		{"svg logo", map[string]any{"display_name": "X", "primary_color": "#0f6cbd", "logo": logoJSON([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>`), "image/svg+xml")}, 422, "svg_not_allowed"},
		{"logo too small", map[string]any{"display_name": "X", "primary_color": "#0f6cbd", "logo": logoJSON(testPNG(t, 8, 8), "image/png")}, 422, "logo_dimensions"},
		{"logo too big", map[string]any{"display_name": "X", "primary_color": "#0f6cbd", "logo": logoJSON(big, "image/png")}, 413, "logo_too_large"},
		{"logo and remove", map[string]any{"display_name": "X", "primary_color": "#0f6cbd", "logo": logoJSON(logo, "image/png"), "remove_logo": true}, 422, "invalid_body"},
		{"not base64", map[string]any{"display_name": "X", "primary_color": "#0f6cbd", "logo": map[string]string{"content_type": "image/png", "data_base64": "!!!"}}, 422, "invalid_logo"},
	} {
		rec := reqDo(h, admin, "PUT", "/api/admin/branding", jsonStr(tc.body))
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.text) {
			t.Errorf("%s: %d %.300s", tc.name, rec.Code, rec.Body)
		}
	}
	if rec := reqDo(h, admin, "GET", "/api/admin/branding", ""); strings.Contains(rec.Body.String(), `"configured":true`) {
		t.Error("a refused change was saved")
	}

	// a valid save: the colour is normalised, the text colour chosen, the logo kept
	rec = reqDo(h, admin, "PUT", "/api/admin/branding", body)
	v = brandingView{}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 || !v.Configured || v.DisplayName != "Larkspur Health" ||
		v.PrimaryColor != "#0f6cbd" || v.OnPrimaryColor != "#ffffff" || v.Logo == nil || v.Logo.Width != 96 || v.Logo.Height != 64 || v.Logo.ContentType != "image/png" {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	// the public page data, and the logo with a strict content type
	code, m := pub(f.B.Slug)
	if code != 200 || m["name"] != "Larkspur Health" || m["primary_color"] != "#0f6cbd" || m["configured"] != true {
		t.Errorf("public: %d %v", code, m)
	}
	url, _ := m["logo_url"].(string)
	if !strings.HasPrefix(url, "/api/auth/branding/logo?tenant="+f.B.Slug) {
		t.Fatalf("logo_url = %v", m["logo_url"])
	}
	lr := serve(h, httptest.NewRequest("GET", url, nil))
	if lr.Code != 200 || lr.Header().Get("Content-Type") != "image/png" || lr.Header().Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(lr.Header().Get("Content-Security-Policy"), "default-src 'none'") || !bytes.Equal(lr.Body.Bytes(), logo) {
		t.Errorf("logo: %d %v len %d", lr.Code, lr.Header(), lr.Body.Len())
	}
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("If-None-Match", lr.Header().Get("ETag"))
	if r2 := serve(h, req); r2.Code != 304 || r2.Body.Len() != 0 {
		t.Errorf("conditional logo: %d", r2.Code)
	}
	// tenant isolation: A sees the default, and has no logo
	if code, m := pub(f.A.Slug); code != 200 || m["name"] != "Tessera" || m["logo_url"] != nil {
		t.Errorf("A's public branding: %d %v", code, m)
	}
	if lr := serve(h, httptest.NewRequest("GET", "/api/auth/branding/logo?tenant="+f.A.Slug, nil)); lr.Code != 404 {
		t.Errorf("A's logo: %d", lr.Code)
	}
	if lr := serve(h, httptest.NewRequest("GET", "/api/auth/branding/logo?tenant=no-such", nil)); lr.Code != 404 {
		t.Errorf("unknown tenant's logo: %d", lr.Code)
	}
	if rec := reqDo(h, adminA, "GET", "/api/admin/branding", ""); strings.Contains(rec.Body.String(), "Larkspur Health") {
		t.Errorf("A's admin sees B's branding: %s", rec.Body)
	}

	// a colour change keeps the logo; removing it clears it; both are audited
	rec = reqDo(h, admin, "PUT", "/api/admin/branding", jsonStr(map[string]any{"display_name": "Larkspur", "primary_color": "#ffe08a"}))
	v = brandingView{}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != 200 || v.OnPrimaryColor != "#000000" || v.Logo == nil {
		t.Errorf("colour change: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "PUT", "/api/admin/branding", jsonStr(map[string]any{"display_name": "Larkspur", "primary_color": "#ffe08a", "remove_logo": true}))
	v = brandingView{}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != 200 || v.Logo != nil {
		t.Errorf("remove logo: %d %s", rec.Code, rec.Body)
	}
	if lr := serve(h, httptest.NewRequest("GET", url, nil)); lr.Code != 404 {
		t.Errorf("removed logo: %d", lr.Code)
	}
	if n := reqAuditActions(t, f, f.B.ID)["branding.updated"]; n != 3 {
		t.Errorf("%d branding.updated events, want 3", n)
	}
}
