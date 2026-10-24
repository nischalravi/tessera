package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
)

// A ServiceNow target (issue #559) takes a JSON credential (basic or OAuth, optionally ticket mode), checked before
// it is sealed, never echoed; the host is on the ServiceNow allow-list; write-back stays off unless the request
// turns it on.
func TestProvisioning_ServiceNowTargetConfig(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	basic, _ := json.Marshal(`{"auth":"basic","username":"tessera.integration","password":"pw-secret-1"}`)
	oauth, _ := json.Marshal(`{"auth":"oauth","client_id":"cid-1","client_secret":"cs-secret-1","mode":"ticket","assignment_group":"0000000000000000000000000000a001"}`)
	const host = `"base_url":"https://acme.service-now.com"`
	for name, body := range map[string]string{
		"no credential":    `{"kind":"servicenow",` + host + `}`,
		"bare token":       `{"kind":"servicenow",` + host + `,"token":"abc"}`,
		"user:secret":      `{"kind":"servicenow",` + host + `,"token":"u:p"}`,
		"unknown auth":     `{"kind":"servicenow",` + host + `,"token":"{\"auth\":\"saml\"}"}`,
		"basic with oauth": `{"kind":"servicenow",` + host + `,"token":"{\"auth\":\"basic\",\"username\":\"u\",\"password\":\"p\",\"client_id\":\"c\"}"}`,
		"group, no ticket": `{"kind":"servicenow",` + host + `,"token":"{\"auth\":\"basic\",\"username\":\"u\",\"password\":\"p\",\"assignment_group\":\"0000000000000000000000000000a001\"}"}`,
		"other host":       `{"kind":"servicenow","base_url":"https://acme.example.com","token":` + string(basic) + `}`,
		"look-alike host":  `{"kind":"servicenow","base_url":"https://service-now.com.evil.example","token":` + string(basic) + `}`,
		"bare domain":      `{"kind":"servicenow","base_url":"https://service-now.com","token":` + string(basic) + `}`,
		"with a path":      `{"kind":"servicenow","base_url":"https://acme.service-now.com/api","token":` + string(basic) + `}`,
		"dialect":          `{"kind":"servicenow",` + host + `,"token":` + string(basic) + `,"dialect":"entra"}`,
		"api root":         `{"kind":"servicenow",` + host + `,"token":` + string(basic) + `,"api_root":"/x"}`,
	} {
		rec := h.c.do("PUT", "/api/provisioning/targets/"+h.conn, body)
		if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d: %s", name, rec.Code, rec.Body)
		}
		for _, leak := range []string{"pw-secret-1", "evil.example", "acme.example.com"} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Errorf("%s: the error echoes %q: %s", name, leak, rec.Body)
			}
		}
	}
	v := h.target(`{"kind":"servicenow","base_url":"https://acme.servicenowservices.com","token":`+string(basic)+`}`, 200)
	if v["kind"] != "servicenow" || v["has_credential"] != true || v["write_back"] != false {
		t.Errorf("target = %v", v)
	}
	v = h.target(`{"kind":"servicenow",`+host+`,"token":`+string(oauth)+`,"write_back":true}`, 200)
	if v["kind"] != "servicenow" || v["write_back"] != true {
		t.Errorf("target = %v", v)
	}
	body, _ := json.Marshal(v)
	for _, leak := range []string{"pw-secret-1", "cs-secret-1", "cid-1", "tessera.integration"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("the response carries %q", leak)
		}
	}
	// the stored credential does not follow the target to another host
	if rec := h.c.do("PUT", "/api/provisioning/targets/"+h.conn, `{"kind":"servicenow","base_url":"https://other.service-now.com"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("a moved target kept its credential: %d %s", rec.Code, rec.Body)
	}
}

// An Atlassian target (issue #559) takes a JSON credential (account e-mail and API token); the host is a
// *.atlassian.net site; accounts are provisioned by the SCIM target, not here.
func TestProvisioning_AtlassianTargetConfig(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	cred, _ := json.Marshal(`{"email":"tessera@acme.example","api_token":"ATATT-secret-token"}`)
	const host = `"base_url":"https://acme.atlassian.net"`
	for name, body := range map[string]string{
		"no credential":   `{"kind":"atlassian",` + host + `}`,
		"bare token":      `{"kind":"atlassian",` + host + `,"token":"ATATT-secret-token"}`,
		"no email":        `{"kind":"atlassian",` + host + `,"token":"{\"api_token\":\"t\"}"}`,
		"other host":      `{"kind":"atlassian","base_url":"https://acme.example.com","token":` + string(cred) + `}`,
		"look-alike host": `{"kind":"atlassian","base_url":"https://acme.atlassian.net.evil.example","token":` + string(cred) + `}`,
		"admin api host":  `{"kind":"atlassian","base_url":"https://api.atlassian.com","token":` + string(cred) + `}`,
		"with a path":     `{"kind":"atlassian","base_url":"https://acme.atlassian.net/wiki","token":` + string(cred) + `}`,
		"dialect":         `{"kind":"atlassian",` + host + `,"token":` + string(cred) + `,"dialect":"entra"}`,
	} {
		rec := h.c.do("PUT", "/api/provisioning/targets/"+h.conn, body)
		if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d: %s", name, rec.Code, rec.Body)
		}
		for _, leak := range []string{"ATATT-secret-token", "evil.example", "acme.example.com"} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Errorf("%s: the error echoes %q: %s", name, leak, rec.Body)
			}
		}
	}
	v := h.target(`{"kind":"atlassian",`+host+`,"token":`+string(cred)+`}`, 200)
	if v["kind"] != "atlassian" || v["has_credential"] != true || v["write_back"] != false {
		t.Errorf("target = %v", v)
	}
	if body, _ := json.Marshal(v); strings.Contains(string(body), "ATATT") || strings.Contains(string(body), "tessera@acme.example") {
		t.Error("the response carries the credential")
	}
}
