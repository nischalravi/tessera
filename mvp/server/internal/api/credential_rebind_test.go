package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestCredentialRebindAPI: moving a SIEM sink or an alert webhook to another
// origin without a new credential is 422 credential_required (#332).
func TestCredentialRebindAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	snd := &okSender{}
	h := siemServer(t, f, snd)
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	rec := siemDo(h, admin, "POST", "/api/siem/sinks",
		`{"name":"Splunk","kind":"webhook","format":"json","target":"https://splunk-a.example/services/collector","flavor":"hec","token":"hec-T"}`)
	var v sinkView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 201 {
		t.Fatalf("create sink: %d %s", rec.Code, rec.Body)
	}
	move := `{"name":"Splunk","format":"json","flavor":"hec","target":"https://evil.example/collector"}`
	// moving the sink to another origin is a two-admin change since issue #520 (siem.sink.target, which clears the token)
	if rec := siemDo(h, admin, "PUT", "/api/siem/sinks/"+v.ID, move); rec.Code != 409 || !strings.Contains(rec.Body.String(), `"two_admin_change_required"`) {
		t.Errorf("sink origin change: %d %s", rec.Code, rec.Body)
	}
	if rec := siemDo(h, admin, "PUT", "/api/siem/sinks/"+v.ID, `{"name":"Splunk","format":"json","flavor":"hec","target":"https://splunk-a.example/services/collector/event"}`); rec.Code != 200 {
		t.Errorf("sink path change: %d %s", rec.Code, rec.Body)
	}
	if rec := siemDo(h, admin, "POST", "/api/siem/sinks/"+v.ID+"/test", ""); rec.Code != 200 || snd.n != 1 {
		t.Errorf("test: %d %s", rec.Code, rec.Body)
	}

	ha := alertsServer(t, f)
	rec = alertsDo(ha, admin, "POST", "/api/alerts/channels", `{"name":"Hook","kind":"webhook","target":"https://hooks.example/a","min_severity":"low"}`)
	var c struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || rec.Code != 201 {
		t.Fatalf("create channel: %d %s", rec.Code, rec.Body)
	}
	if rec := alertsDo(ha, admin, "PUT", "/api/alerts/channels/"+c.ID, `{"name":"Hook","target":"https://evil.example/a"}`); rec.Code != 422 ||
		!strings.Contains(rec.Body.String(), `"credential_required"`) {
		t.Errorf("channel origin change: %d %s", rec.Code, rec.Body)
	}
	if rec := alertsDo(ha, admin, "PUT", "/api/alerts/channels/"+c.ID, `{"name":"Hook","target":"https://evil.example/a","rotate_secret":true}`); rec.Code != 200 {
		t.Errorf("channel origin change with rotation: %d %s", rec.Code, rec.Body)
	}
}
