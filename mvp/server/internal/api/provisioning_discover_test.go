package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
)

// Discovery records whether a SCIM target advertises the Agent resource, keeps the failure when it cannot
// read the documents, survives an edit that leaves the destination alone, and never touches provisioning (#542).
func TestProvisioning_DiscoverRecordsAgentSupport(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	if rec := h.c.do("POST", "/api/provisioning/targets/"+h.conn+"/discover", ``); rec.Code != 404 {
		t.Errorf("a connection without a target: %d %s", rec.Code, rec.Body)
	}
	// the fake serves no discovery documents: the failure is recorded, not raised
	h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"tok","write_back":true}`, 200)
	out := h.c.json("POST", "/api/provisioning/targets/"+h.conn+"/discover", ``, 200).(map[string]any)
	if out["agent_advertised"] != false || out["error"] == "" || out["error"] == nil || out["checked_at"] == "" {
		t.Fatalf("failed discovery = %v", out)
	}
	if got := h.c.json("GET", "/api/provisioning/targets", "", 200).([]any)[0].(map[string]any)["discovery"]; got == nil {
		t.Error("the target view has no discovery")
	}
	// Users/Groups provisioning still works after a failed discovery
	h.c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, h.edgeID("alice", "eng")), 200)

	var mu sync.Mutex
	paths := []string{}
	ds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		switch r.URL.Path {
		case "/scim/v2/ServiceProviderConfig":
			_, _ = w.Write([]byte(`{"patch":{"supported":true},"vendorThing":{"a":1}}`))
		case "/scim/v2/ResourceTypes":
			_, _ = w.Write([]byte(`{"Resources":[{"name":"User"},{"name":"Agent","schema":"urn:ietf:params:scim:schemas:core:2.0:Agent"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ds.Close()
	h.target(`{"kind":"scim","base_url":"`+ds.URL+`/scim/v2","token":"tok","write_back":true}`, 200)
	out = h.c.json("POST", "/api/provisioning/targets/"+h.conn+"/discover", ``, 200).(map[string]any)
	if out["agent_advertised"] != true || out["service_provider_config"] != true || out["error"] != nil {
		t.Fatalf("discovery = %v", out)
	}
	mu.Lock()
	for _, p := range paths {
		if !strings.HasPrefix(p, "GET ") || !strings.HasSuffix(p, "Bearer tok") {
			t.Errorf("request %q", p)
		}
	}
	mu.Unlock()
	// an edit that keeps the origin keeps the finding
	v := h.target(`{"kind":"scim","base_url":"`+ds.URL+`/scim/v2","write_back":false}`, 200)
	if d, _ := v["discovery"].(map[string]any); d == nil || d["agent_advertised"] != true {
		t.Errorf("edit lost discovery: %v", v)
	}
	if !strings.Contains(h.audit(), "provision.discover") {
		t.Errorf("audit = %s", h.audit())
	}
}
