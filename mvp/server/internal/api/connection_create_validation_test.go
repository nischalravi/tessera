package api

import (
	"net/http"
	"strings"
	"testing"
)

// POST /api/connections runs the same checks as PATCH .../config on the settings it is given, and
// refuses cloud metadata hosts in every environment (#574).
func TestCreateConnection_ValidatesSuppliedConfig(t *testing.T) {
	t.Parallel()
	rest := func(base string) string {
		return `{"name":"REST","connector_type":"rest_generic","config":{"rest":{"base_url":"` + base + `","auth":{"type":"bearer"},
		  "users":{"path":"/users","fields":{"id":"$.id","username":"$.login"}}}}}`
	}
	cases := []struct {
		name, env, body string
		status          int
		field           string // a field the error names
	}{
		{"rest spec missing", "dev", `{"name":"REST","connector_type":"rest_generic","config":{"technical_owner":"Ingrid"}}`, http.StatusUnprocessableEntity, "rest"},
		{"rest spec malformed", "dev", `{"name":"REST","connector_type":"rest_generic","config":{"rest":{"base_url":"not a url"}}}`, http.StatusUnprocessableEntity, "rest.base_url"},
		{"gcp metadata name", "dev", rest("https://metadata.google.internal/computeMetadata"), http.StatusUnprocessableEntity, "rest.base_url"},
		{"gcp metadata name, prod", "prod", rest("https://metadata.google.internal"), http.StatusUnprocessableEntity, "rest.base_url"},
		{"gcp metadata name, upper case and dot", "dev", rest("https://Metadata.Google.Internal./x"), http.StatusUnprocessableEntity, "rest.base_url"},
		{"aws metadata ip over http", "dev", rest("http://169.254.169.254/latest"), http.StatusUnprocessableEntity, "rest.base_url"},
		{"aws metadata ip over https", "prod", rest("https://169.254.169.254"), http.StatusUnprocessableEntity, "rest.base_url"},
		{"aws ipv6 metadata", "dev", rest("http://[fd00:ec2::254]/latest"), http.StatusUnprocessableEntity, "rest.base_url"},
		{"valid rest spec", "dev", rest("https://api.example.com"), http.StatusCreated, ""},
		{"scim metadata base url", "prod", `{"name":"S","connector_type":"scim_app","config":{"base_url":"https://169.254.169.254"}}`, http.StatusUnprocessableEntity, "base_url"},
		{"okta metadata org url", "dev", `{"name":"O","connector_type":"okta","config":{"org_url":"https://metadata.google.internal"}}`, http.StatusUnprocessableEntity, "org_url"},
		{"ldap metadata host", "dev", `{"name":"O","connector_type":"ldap","config":{"host":"fd00:ec2::254"}}`, http.StatusUnprocessableEntity, "host"},
		// shape problems of the other types stay advisory, as on PATCH
		{"scim base url not https is advisory", "dev", `{"name":"S","connector_type":"scim_app","config":{"base_url":"ftp://x.example.com"}}`, http.StatusCreated, ""},
		// a draft is still created blank, then filled in by the wizard
		{"blank rest draft", "dev", `{"name":"REST","connector_type":"rest_generic"}`, http.StatusCreated, ""},
		{"blank okta draft", "prod", `{"name":"O","connector_type":"okta"}`, http.StatusCreated, ""},
		{"scim preset only", "dev", `{"name":"S","connector_type":"scim_app","config":{"preset":"slack"}}`, http.StatusCreated, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newRD(t, func(cfg *Config) { cfg.Env = tc.env })
			v := c.json("POST", "/api/connections", tc.body, tc.status)
			if tc.status == http.StatusCreated {
				return
			}
			if v["error"] != "invalid_config" || !strings.Contains(toJSON(v["fields"]), `"`+tc.field+`"`) {
				t.Errorf("%v", v)
			}
			// nothing was saved
			list := c.do("GET", "/api/connections", "").Body.String()
			if strings.Contains(list, `"name":"REST"`) || strings.Contains(list, `"name":"O"`) || strings.Contains(list, `"name":"S"`) {
				t.Errorf("a refused connection was saved: %s", list)
			}
		})
	}
}

// The same hosts are refused when the spec is patched in (the shape check ran without a policy before).
func TestPatchConfig_RefusesMetadataHosts(t *testing.T) {
	t.Parallel()
	c := newRD(t, func(cfg *Config) { cfg.Env = "dev" })
	v := c.json("POST", "/api/connections", `{"name":"REST","connector_type":"rest_generic"}`, http.StatusCreated)
	id := v["id"].(string)
	for _, h := range []string{"https://metadata.google.internal", "http://169.254.169.254"} {
		c.json("PATCH", "/api/connections/"+id+"/config", `{"rest":{"base_url":"`+h+`","auth":{"type":"bearer"},"users":{"path":"/u","fields":{"id":"$.id","username":"$.u"}}}}`, http.StatusUnprocessableEntity)
	}
	o := c.json("POST", "/api/connections", `{"name":"Okta","connector_type":"okta"}`, http.StatusCreated)["id"].(string)
	c.json("PATCH", "/api/connections/"+o+"/config", `{"org_url":"https://metadata.google.internal"}`, http.StatusUnprocessableEntity)
}
