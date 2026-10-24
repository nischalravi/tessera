package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
)

// The preset library is served as typed data, and a SCIM target can name one;
// anything else is refused at the API boundary.
func TestSCIMPresets_ListAndTargetPreset(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	list := h.c.json("GET", "/api/scim/presets", "", 200).([]any)
	if len(list) != 12 {
		t.Fatalf("%d presets", len(list))
	}
	slack := list[0].(map[string]any)
	if slack["id"] != "slack" || slack["category"] != "Cloud & SaaS" || slack["auth"] != "bearer_token" {
		t.Fatalf("slack = %v", slack)
	}
	if q := slack["quirks"].(map[string]any); q["op_case"] != "lower" || q["bool_as_string"] != "unknown" {
		t.Fatalf("quirks = %v", q)
	}

	body := func(extra string) string {
		return `{"kind":"scim","base_url":"` + h.url + `","token":"tok","write_back":true` + extra + `}`
	}
	if v := h.target(body(`,"preset":"slack"`), 200); v["preset"] != "slack" {
		t.Fatalf("view = %v", v)
	}
	h.target(body(`,"preset":"nope"`), 422)
	h.target(`{"kind":"okta","base_url":"`+h.url+`","token":"tok","preset":"slack"}`, 422)
}

// Discovery records the advertised capabilities with the target.
func TestSCIMPresets_DiscoveryRecordsCapabilities(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	ds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scim/v2/ServiceProviderConfig":
			_, _ = w.Write([]byte(`{"patch":{"supported":false},"filter":{"supported":true,"maxResults":50},"etag":{"supported":true}}`))
		case "/scim/v2/ResourceTypes":
			_, _ = w.Write([]byte(`{"Resources":[{"name":"User"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ds.Close()
	h.target(`{"kind":"scim","base_url":"`+ds.URL+`/scim/v2","token":"tok","write_back":true,"preset":"auth0"}`, 200)
	out := h.c.json("POST", "/api/provisioning/targets/"+h.conn+"/discover", ``, 200).(map[string]any)
	c, _ := out["capabilities"].(map[string]any)
	if c == nil || c["patch"] != "no" || c["filter"] != "yes" || c["etag"] != "yes" || c["bulk"] != "unknown" || c["filter_max_results"] != float64(50) {
		t.Fatalf("capabilities = %v", out)
	}
}
