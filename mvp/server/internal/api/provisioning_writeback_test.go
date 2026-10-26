package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen/fakerest"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Turning provisioning write-back on is a two-admin change for every target kind (issue #569); turning it off,
// or narrowing what a target writes, stays one admin.

// wbBodies is a valid PUT body of every target kind, with write-back as asked.
func wbBodies(t *testing.T, restURL string) map[string]func(wb bool) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	sf, _ := json.Marshal(map[string]string{"client_id": "3MVG9-key", "username": "tessera@acme.example", "private_key": pemKey})
	sfq, _ := json.Marshal(string(sf))
	snow, _ := json.Marshal(`{"auth":"basic","username":"tessera.integration","password":"pw-secret-1"}`)
	atl, _ := json.Marshal(`{"email":"tessera@acme.example","api_token":"ATATT-secret-token"}`)
	ldapCfg := `{"host":"ldap.acme.example","bind_dn":"cn=svc,dc=acme,dc=example","write_scope":["ou=People,dc=acme,dc=example"],` +
		`"user_base":"ou=People,dc=acme,dc=example","user_dn_template":"uid=${account},ou=People,dc=acme,dc=example",` +
		`"user_attrs":{"uid":"${account}","employeeNumber":"${user.external_id}"},"match_attr":"employeeNumber"}`
	sqlCfg := `{"engine":"postgres","host":"db.example.com","database":"app","username":"tessera","mode":"native"}`
	rest := strings.Replace(restSpec, "%s", restURL, 1)
	with := func(f string) func(bool) string {
		return func(wb bool) string { return fmt.Sprintf(f, wb) }
	}
	return map[string]func(bool) string{
		"scim":        with(`{"kind":"scim","base_url":"https://scim.example/scim/v2","token":"tok","write_back":%t}`),
		"okta":        with(`{"kind":"okta","base_url":"https://acme.okta.com","token":"tok","write_back":%t}`),
		"fake":        with(`{"kind":"fake","write_back":%t}`),
		"cyberark":    with(`{"kind":"cyberark","base_url":"https://vault.example.com","token":"svc:k3y","write_back":%t}`),
		"delinea":     with(`{"kind":"delinea","base_url":"https://vault.example.com","token":"svc:k3y","write_back":%t}`),
		"beyondtrust": with(`{"kind":"beyondtrust","base_url":"https://bt.example.com","token":"svc:k3y","write_back":%t}`),
		"sap":         with(`{"kind":"sap","base_url":"https://s4.example.com","token":"client:s3cr3t","write_back":%t}`),
		"oracle":      with(`{"kind":"oracle","base_url":"https://erp.example.com","token":"client:s3cr3t","write_back":%t}`),
		"salesforce":  with(`{"kind":"salesforce","base_url":"https://acme.my.salesforce.com","token":` + string(sfq) + `,"write_back":%t}`),
		"servicenow":  with(`{"kind":"servicenow","base_url":"https://acme.service-now.com","token":` + string(snow) + `,"write_back":%t}`),
		"atlassian":   with(`{"kind":"atlassian","base_url":"https://acme.atlassian.net","token":` + string(atl) + `,"write_back":%t}`),
		"sql":         with(`{"kind":"sql","token":"pw","sql":` + sqlCfg + `,"write_back":%t}`),
		"ldap":        with(`{"kind":"ldap","token":"bind-pw","ldap":` + ldapCfg + `,"write_back":%t}`),
		"ad":          with(`{"kind":"ad","token":"bind-pw","ldap":` + ldapCfg + `,"write_back":%t}`),
		"rest":        with(`{"kind":"rest","base_url":"` + restURL + `","rest":` + strings.ReplaceAll(rest, "%", "%%") + `,"token":"sec-1","write_back":%t}`),
	}
}

// wbEnv is the provisioning harness plus a second tenant admin.
type wbEnv struct {
	*provHarness
	other   client
	restURL string
}

func newWBEnv(t *testing.T) (*wbEnv, func()) {
	t.Helper()
	h := newProvHarness(t, fake.Options{})
	h.srv.cfg.Env = config.Dev // the fake REST system is plain http on loopback
	h.srv.Provisioning().Runtime = connsync.Runtime{Env: config.Dev, AllowLoopback: true}
	f := fakerest.New(3)
	f.Auth = "oauth2"
	l := signIn(t, h.st.DB, h.st.Tenant, authtest.User{Email: "second.admin@larkspur.example", Display: "Second Admin",
		Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, testkit.Now)
	e := &wbEnv{provHarness: h, other: client{t, l.Handler(h.srv.Handler())}}
	e.restURL = f.URL
	return e, f.Close
}

// request files the write-back change for the target as it stands and returns its id and payload hash.
func (e *wbEnv) request(hash string) (id, payloadHash string) {
	e.t.Helper()
	body := fmt.Sprintf(`{"type":%q,"payload":{"connection_id":%q,"config_hash":%q}}`, admin.TypeProvWriteBackEnable, e.conn, hash)
	v := e.c.json("POST", "/api/admin/change-requests", body, http.StatusCreated).(map[string]any)
	if v["status"] != "pending_approval" || v["two_person"] != true || !strings.Contains(asString(v["summary"]), "Enable write-back") {
		e.t.Fatalf("request = %v", v)
	}
	return asString(v["id"]), asString(v["payload_hash"])
}

func (e *wbEnv) approve(c client, id, hash string, want int) map[string]any {
	e.t.Helper()
	return c.json("POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash), want).(map[string]any)
}

func (e *wbEnv) view() map[string]any {
	e.t.Helper()
	return e.c.json("GET", "/api/provisioning/targets", "", 200).([]any)[0].(map[string]any)
}

func TestProvisioning_WriteBackNeedsSecondAdmin_AllKinds(t *testing.T) {
	e, closeRest := newWBEnv(t)
	defer closeRest()
	bodies := wbBodies(t, e.restURL)
	for kind, body := range bodies {
		t.Run(kind, func(t *testing.T) {
			e.t = t
			e.c.do("DELETE", "/api/provisioning/targets/"+e.conn, "")
			// asking for write-back saves the configuration with write-back still off
			v := e.target(strings.Replace(body(true), `"write_back":true`, `"write_back":false`, 1), 200)
			if v["write_back"] != false || v["write_back_pending"] != nil {
				t.Fatalf("saved without write-back = %v", v)
			}
			rec := e.c.json("PUT", "/api/provisioning/targets/"+e.conn, body(true), 200).(map[string]any)
			if rec["write_back"] != false || rec["write_back_pending"] != true || len(asString(rec["config_hash"])) != 64 {
				t.Fatalf("PUT write_back:true = %v", rec)
			}
			if e.view()["write_back"] != false {
				t.Fatal("write-back is on before approval")
			}
			id, hash := e.request(asString(rec["config_hash"]))
			// the requester cannot approve, whatever the hash
			if r := e.c.do("POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); r.Code != http.StatusForbidden ||
				!strings.Contains(r.Body.String(), "self_approval_refused") {
				t.Fatalf("self approval: %d %s", r.Code, r.Body)
			}
			if e.view()["write_back"] != false {
				t.Fatal("self-approval enabled write-back")
			}
			if a := e.approve(e.other, id, hash, 200); a["status"] != "applied" {
				t.Fatalf("approved = %v", a)
			}
			if e.view()["write_back"] != true {
				t.Fatal("write-back is off after approval")
			}
			for _, want := range []string{"provision.write_back_enabled", "admin.change.submitted", "admin.change.approved", "admin.change.applied"} {
				if !strings.Contains(e.audit(), want) {
					t.Errorf("audit has no %s: %s", want, e.audit())
				}
			}
			// turning it off is one admin and immediate
			if v := e.c.json("PUT", "/api/provisioning/targets/"+e.conn, body(false), 200).(map[string]any); v["write_back"] != false || v["write_back_pending"] != nil {
				t.Errorf("turning off = %v", v)
			}
			if e.view()["write_back"] != false {
				t.Error("write-back stayed on")
			}
		})
	}
	if len(bodies) != 15 {
		t.Errorf("%d kinds covered, want 15", len(bodies))
	}
}

func TestProvisioning_WriteBackRequestIsBoundToWhatWasReviewed(t *testing.T) {
	e, closeRest := newWBEnv(t)
	defer closeRest()
	scim := func(url, extra string) string {
		return `{"kind":"scim","base_url":"` + url + `","write_back":true` + extra + `}`
	}
	v := e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim("https://scim.example/scim/v2", `,"token":"tok"`), 200).(map[string]any)
	id, hash := e.request(asString(v["config_hash"]))
	// the target is edited after the request: approving it is refused, not applied to the new configuration
	e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim("https://scim.example/scim/v2", `,"on_deprovision":"delete"`), 200)
	if r := e.other.do("POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); r.Code != http.StatusConflict ||
		!strings.Contains(r.Body.String(), "stale_target") {
		t.Fatalf("approving a stale request: %d %s", r.Code, r.Body)
	}
	if e.view()["write_back"] != false {
		t.Fatal("a stale request enabled write-back")
	}
	// a bad request is refused at submit: no hash, a hash of something else, an unknown target, a tenant-foreign id
	for name, body := range map[string]string{
		"no hash":      fmt.Sprintf(`{"type":%q,"payload":{"connection_id":%q}}`, admin.TypeProvWriteBackEnable, e.conn),
		"wrong hash":   fmt.Sprintf(`{"type":%q,"payload":{"connection_id":%q,"config_hash":%q}}`, admin.TypeProvWriteBackEnable, e.conn, strings.Repeat("a", 64)),
		"unknown conn": fmt.Sprintf(`{"type":%q,"payload":{"connection_id":%q,"config_hash":%q}}`, admin.TypeProvWriteBackEnable, strings.Repeat("0", 36), strings.Repeat("a", 64)),
		"extra field":  fmt.Sprintf(`{"type":%q,"payload":{"connection_id":%q,"config_hash":%q,"write_back":true}}`, admin.TypeProvWriteBackEnable, e.conn, strings.Repeat("a", 64)),
	} {
		if r := e.c.do("POST", "/api/admin/change-requests", body); r.Code < 400 || r.Code >= 500 {
			t.Errorf("%s: status %d %s", name, r.Code, r.Body)
		}
	}
	// a request for a target whose write-back is already on is refused
	e.c.json("POST", "/api/admin/change-requests/"+id+"/cancel", "", 200) // the stale one still waits
	cur := e.view()
	id, hash = e.request(asString(cur["config_hash"]))
	e.approve(e.other, id, hash, 200)
	body := fmt.Sprintf(`{"type":%q,"payload":{"connection_id":%q,"config_hash":%q}}`, admin.TypeProvWriteBackEnable, e.conn, asString(e.view()["config_hash"]))
	if r := e.c.do("POST", "/api/admin/change-requests", body); r.Code != http.StatusConflict {
		t.Errorf("enable when already on: %d %s", r.Code, r.Body)
	}
}

func TestProvisioning_WriteBackWideningNeedsSecondAdmin(t *testing.T) {
	e, closeRest := newWBEnv(t)
	defer closeRest()
	scim := func(extra string) string {
		return `{"kind":"scim","base_url":"https://scim.example/scim/v2","write_back":true` + extra + `}`
	}
	v := e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim(`,"token":"tok"`), 200).(map[string]any)
	id, hash := e.request(asString(v["config_hash"]))
	e.approve(e.other, id, hash, 200)
	// the same settings, and a narrowing, are one admin
	e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim(``), 200)
	// delete on deprovision, another origin, another agent, a preset or a dialect widen what it may write
	for name, body := range map[string]string{
		"delete":  scim(`,"on_deprovision":"delete"`),
		"origin":  strings.Replace(scim(``), "scim.example", "scim.other.example", 1) + "",
		"preset":  scim(`,"preset":"auth0"`),
		"dialect": scim(`,"dialect":"entra"`),
	} {
		if name == "origin" {
			body = strings.Replace(body, `"write_back":true`, `"write_back":true,"token":"tok2"`, 1)
		}
		r := e.c.do("PUT", "/api/provisioning/targets/"+e.conn, body)
		if r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "two_admin_change_required") ||
			!strings.Contains(r.Body.String(), admin.TypeProvWriteBackEnable) {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	if w := e.view(); w["write_back"] != true || w["on_deprovision"] != nil {
		t.Errorf("a refused widening changed the target: %v", w)
	}
	// the route the refusal names: turn off (one admin), edit, then ask for two admins
	e.c.json("PUT", "/api/provisioning/targets/"+e.conn, strings.Replace(scim(`,"on_deprovision":"delete"`), `"write_back":true`, `"write_back":false`, 1), 200)
	w := e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim(`,"on_deprovision":"delete"`), 200).(map[string]any)
	if w["write_back"] != false || w["write_back_pending"] != true || w["on_deprovision"] != "delete" {
		t.Fatalf("re-enabling = %v", w)
	}
	// narrowing from delete back to disable is one admin once write-back is on
	id, hash = e.request(asString(w["config_hash"]))
	e.approve(e.other, id, hash, 200)
	if v := e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim(``), 200).(map[string]any); v["write_back"] != true || v["on_deprovision"] != nil {
		t.Errorf("narrowing = %v", v)
	}
}

func TestProvisioning_RESTWriteBackOperations(t *testing.T) {
	e, closeRest := newWBEnv(t)
	defer closeRest()
	credSent := false // the credential goes with the first save only: a new one on a writing target is a widening
	rest := func(spec string) string {
		tok := `,"token":"sec-1"`
		if credSent {
			tok = ""
		}
		credSent = true
		return `{"kind":"rest","base_url":"` + e.restURL + `","rest":` + spec + tok + `,"write_back":true}`
	}
	full := strings.Replace(restSpec, "%s", e.restURL, 1)
	narrow := strings.Replace(full, `,
    "disable": {"method": "PATCH", "path": "/users/{external_id}", "body": {"state": "suspended"}}`, "", 1)
	wider := strings.Replace(full, `"disable":`, `"delete": {"method": "DELETE", "path": "/users/{external_id}"}, "disable":`, 1)
	if narrow == full || wider == full {
		t.Fatal("the spec fixture changed")
	}
	v := e.c.json("PUT", "/api/provisioning/targets/"+e.conn, rest(full), 200).(map[string]any)
	id, hash := e.request(asString(v["config_hash"]))
	e.approve(e.other, id, hash, 200)
	// a new operation (delete) on a target that writes needs the two-admin route; dropping one does not
	if r := e.c.do("PUT", "/api/provisioning/targets/"+e.conn, rest(wider)); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "two_admin_change_required") {
		t.Errorf("a new operation: %d %s", r.Code, r.Body)
	}
	if r := e.c.do("PUT", "/api/provisioning/targets/"+e.conn, rest(narrow)); r.Code != http.StatusOK {
		t.Errorf("dropping an operation: %d %s", r.Code, r.Body)
	}
	if e.view()["write_back"] != true {
		t.Error("narrowing turned write-back off")
	}
}

func TestProvisioning_WriteBackCredentialAndStaleRequests(t *testing.T) {
	e, closeRest := newWBEnv(t)
	defer closeRest()
	scim := func(wb bool, token string) string {
		tok := ""
		if token != "" {
			tok = `,"token":"` + token + `"`
		}
		return fmt.Sprintf(`{"kind":"scim","base_url":"https://scim.example/scim/v2","write_back":%t%s}`, wb, tok)
	}
	put := func(body string) *httptest.ResponseRecorder {
		return e.c.do("PUT", "/api/provisioning/targets/"+e.conn, body)
	}
	// a new credential on a target that is not writing is allowed
	if r := put(scim(false, "tok-1")); r.Code != 200 {
		t.Fatalf("credential on a non-writing target: %d %s", r.Code, r.Body)
	}
	v := e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim(true, "tok-2"), 200).(map[string]any)
	if v["write_back_pending"] != true {
		t.Fatalf("pending = %v", v)
	}
	id, hash := e.request(asString(v["config_hash"]))
	// a second request while one waits is refused
	body := fmt.Sprintf(`{"type":%q,"payload":{"connection_id":%q,"config_hash":%q}}`, admin.TypeProvWriteBackEnable, e.conn, asString(v["config_hash"]))
	if r := e.c.do("POST", "/api/admin/change-requests", body); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "invalid_state") {
		t.Errorf("second request: %d %s", r.Code, r.Body)
	}
	// a credential-only edit between request and approval makes the request stale
	if r := put(scim(false, "tok-3")); r.Code != 200 {
		t.Fatalf("edit: %d %s", r.Code, r.Body)
	}
	if r := e.other.do("POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); r.Code != http.StatusConflict ||
		!strings.Contains(r.Body.String(), "stale_target") {
		t.Fatalf("stale approval: %d %s", r.Code, r.Body)
	}
	if e.view()["write_back"] != false {
		t.Fatal("a stale request enabled write-back")
	}
	// a target deleted before approval: nothing to enable
	e.c.json("POST", "/api/admin/change-requests/"+id+"/cancel", "", 200)
	v = e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim(true, ""), 200).(map[string]any)
	id, hash = e.request(asString(v["config_hash"]))
	e.c.json("DELETE", "/api/provisioning/targets/"+e.conn, "", 200)
	if r := e.other.do("POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); r.Code != http.StatusNotFound {
		t.Errorf("approving for a deleted target: %d %s", r.Code, r.Body)
	}
	e.c.json("POST", "/api/admin/change-requests/"+id+"/cancel", "", 200)
	// a new credential on a target that is writing needs the two-admin route
	e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim(false, "tok-4"), 200)
	v = e.c.json("PUT", "/api/provisioning/targets/"+e.conn, scim(true, ""), 200).(map[string]any)
	id, hash = e.request(asString(v["config_hash"]))
	e.approve(e.other, id, hash, 200)
	if r := put(scim(true, "tok-5")); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "two_admin_change_required") {
		t.Errorf("credential change on a writing target: %d %s", r.Code, r.Body)
	}
	if r := put(scim(true, "")); r.Code != 200 {
		t.Errorf("an edit that changes nothing: %d %s", r.Code, r.Body)
	}
	bad := `{"type":"` + admin.TypeProvWriteBackEnable + `","payload":{"connection_id":"not-a-uuid-not-a-uuid-not-a-uuid-xxxx","config_hash":"` + strings.Repeat("z", 64) + `"}}`
	if r := e.c.do("POST", "/api/admin/change-requests", bad); r.Code != 422 {
		t.Errorf("malformed ids: %d %s", r.Code, r.Body)
	}
}
