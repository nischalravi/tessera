package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// fetchSpec reads /api/openapi.json as the signed-in admin.
func fetchSpec(t *testing.T) (oamap, *Server) {
	t.Helper()
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	var doc oamap
	b := srvSpec(t, srv)
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, srv
}

func srvSpec(t *testing.T, srv *Server) []byte {
	t.Helper()
	b, err := srv.fullOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var openAPIMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "patch": true, "head": true, "options": true}

// TestOpenAPI_MatchesRouteTable: every registered route is in the document
// and the document lists no route that is not registered.
func TestOpenAPI_MatchesRouteTable(t *testing.T) {
	doc, srv := fetchSpec(t)
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi = %v", doc["openapi"])
	}
	paths := doc["paths"].(oamap)
	registered := map[string]bool{}
	for _, rt := range srv.Routes() {
		key := rt.Method + " " + rt.Pattern
		if registered[key] {
			t.Errorf("%s is registered twice", key)
		}
		registered[key] = true
		item, _ := paths[rt.Pattern].(oamap)
		if _, ok := item[strings.ToLower(rt.Method)].(oamap); !ok {
			t.Errorf("registered route %s is missing from the OpenAPI document", key)
		}
	}
	for pat, v := range paths {
		for m := range v.(oamap) {
			if !openAPIMethods[m] {
				continue
			}
			if !registered[strings.ToUpper(m)+" "+pat] {
				t.Errorf("the OpenAPI document lists %s %s, which is not a registered route", strings.ToUpper(m), pat)
			}
		}
	}
}

// TestOpenAPI_OperationContract: each operation states its parameters,
// responses (with error codes), and the permission and scopes it needs.
func TestOpenAPI_OperationContract(t *testing.T) {
	doc, srv := fetchSpec(t)
	paths := doc["paths"].(oamap)
	ids := map[string]string{}
	pathParam := regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)
	for _, rt := range srv.Routes() {
		key := rt.Method + " " + rt.Pattern
		op := paths[rt.Pattern].(oamap)[strings.ToLower(rt.Method)].(oamap)
		if id, _ := op["operationId"].(string); id == "" || ids[id] != "" {
			t.Errorf("%s: operationId %q is empty or repeated (%s)", key, id, ids[id])
		} else {
			ids[id] = key
		}
		if s, _ := op["summary"].(string); s == "" {
			t.Errorf("%s: no summary", key)
		}
		have := map[string]bool{}
		ps, _ := op["parameters"].([]any)
		for _, p := range ps {
			pm := p.(oamap)
			if pm["in"] == "path" {
				have[pm["name"].(string)] = true
			}
		}
		for _, m := range pathParam.FindAllStringSubmatch(rt.Pattern, -1) {
			if !have[m[1]] {
				t.Errorf("%s: path parameter %s is not documented", key, m[1])
			}
		}
		resp, _ := op["responses"].(oamap)
		if len(resp) == 0 || resp["429"] == nil || resp["503"] == nil {
			t.Errorf("%s: responses = %v", key, resp)
		}
		if rt.Public {
			if op["x-tessera-public"] != true || resp["401"] != nil {
				t.Errorf("%s: public route documented as authenticated", key)
			}
			continue
		}
		if resp["401"] == nil || resp["403"] == nil {
			t.Errorf("%s: no 401/403", key)
		}
		if op["x-tessera-permission"] != string(rt.Perm) || op["x-tessera-step-up"] != (rt.Authn != nil) {
			t.Errorf("%s: permission/step-up = %v/%v, want %s/%v", key, op["x-tessera-permission"], op["x-tessera-step-up"], rt.Perm, rt.Authn != nil)
		}
		scopes, _ := op["x-tessera-scopes"].([]any)
		if len(scopes) != len(auth.ScopesFor(rt.Perm)) {
			t.Errorf("%s: scopes = %v, want %v", key, scopes, auth.ScopesFor(rt.Perm))
		}
		if rt.Method != "GET" && op["requestBody"] == nil {
			t.Errorf("%s: no request body", key)
		}
	}
}

// TestOpenAPI_Refs: every $ref resolves inside the document.
func TestOpenAPI_Refs(t *testing.T) {
	doc, srv := fetchSpec(t)
	raw := string(srvSpec(t, srv))
	comps := doc["components"].(oamap)
	for _, m := range regexp.MustCompile(`"\$ref": "#/components/(\w+)/(\w+)"`).FindAllStringSubmatch(raw, -1) {
		if _, ok := comps[m[1]].(oamap)[m[2]]; !ok {
			t.Errorf("dangling $ref %s", m[0])
		}
	}
}

// TestOpenAPI_Served: the document is served at /api/openapi.json to a
// signed-in caller, is not public, and the Swagger page loads it.
func TestOpenAPI_Served(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	for _, rt := range srv.Routes() {
		if rt.Pattern == "/api/openapi.json" && rt.Public {
			t.Fatal("/api/openapi.json must need a session")
		}
	}
	st := testkit.Demo(t)
	c := client{t, testServer(t, st)}
	rec := c.do(http.MethodGet, "/api/openapi.json", "")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "json") {
		t.Fatalf("status %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	var doc oamap
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || len(doc["paths"].(oamap)) < 400 {
		t.Fatalf("document: %v, %d paths", err, len(doc["paths"].(oamap)))
	}
	if sw := c.do(http.MethodGet, "/docs", ""); !strings.Contains(sw.Body.String(), "/api/openapi.json") {
		t.Error("the Swagger page does not load /api/openapi.json")
	}
	if rd := c.do(http.MethodGet, "/redoc", ""); !strings.Contains(rd.Body.String(), "/api/openapi.json") {
		t.Error("the ReDoc page does not load /api/openapi.json")
	}
}

func TestHumanize(t *testing.T) {
	for in, want := range map[string]string{"listIdentities": "List identities", "health": "Health", "scimListUsers": "Scim list users"} {
		if got := humanize(in); got != want {
			t.Errorf("humanize(%q) = %q, want %q", in, got, want)
		}
	}
}
