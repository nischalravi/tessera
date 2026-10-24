package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen/fakerest"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
)

// restSpec is a REST target's spec: OAuth client credentials, user lookup and
// write operations.
const restSpec = `{
  "auth": {"type": "oauth2_client_credentials", "client_id": "client-1", "token_url": "%s/oauth/token"},
  "users": {"path": "/offset/users", "fields": {"id": "$.id", "username": "$.login"},
            "pagination": {"style": "offset", "offset_param": "offset", "size_param": "limit", "page_size": 10}},
  "writes": {
    "lookup": {"method": "GET", "path": "/users/{username}", "record_path": "$.user"},
    "create": {"method": "POST", "path": "/users", "body": {"login": "${username}", "email": "${email}"}, "expect": [201]},
    "disable": {"method": "PATCH", "path": "/users/{external_id}", "body": {"state": "suspended"}}
  }
}`

func TestProvisioning_RESTTarget(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	// the fake REST system is plain http on loopback, which only a dev server accepts
	h.srv.cfg.Env = config.Dev
	h.srv.Provisioning().Runtime = connsync.Runtime{Env: config.Dev, AllowLoopback: true}
	f := fakerest.New(3)
	defer f.Close()
	f.Auth = "oauth2"
	put := func(base, rest, token string, want int) map[string]any {
		body := `{"kind":"rest","base_url":"` + base + `","rest":` + rest + `,"token":"` + token + `","write_back":false}`
		return h.c.json("PUT", "/api/provisioning/targets/"+h.conn, body, want).(map[string]any)
	}
	spec := strings.Replace(restSpec, "%s", f.URL, 1)

	t.Run("validation names every field", func(t *testing.T) {
		bad := `{"auth":{"type":"basic"},"users":{"path":"users","fields":{"id":"$..id"}},"writes":{"delete":{"method":"GET","path":"/u/{secret}"}}}`
		out := put(f.URL, bad, "x", 422)
		fields, _ := out["fields"].([]any)
		got := map[string]bool{}
		for _, fl := range fields {
			got[fl.(map[string]any)["field"].(string)] = true
		}
		for _, want := range []string{"auth.username", "users.path", "users.fields.id", "users.fields.username", "writes.lookup", "writes.delete.method"} {
			if !got[want] {
				t.Errorf("no error on %s in %v", want, out)
			}
		}
		if out["error"] != "invalid_rest" {
			t.Errorf("code = %v", out["error"])
		}
	})
	t.Run("other rejections", func(t *testing.T) {
		put(f.URL, spec, "", 422)                                                                                        // no credential
		put(f.URL, `{"auth":{"type":"bearer"},"users":{"path":"/u","fields":{"id":"$.id","username":"$.u"}}}`, "t", 422) // no writes
		put(f.URL, `{"auth":{"type":"bearer","token":"hunter2"}}`, "t", 422)                                             // a secret in the spec
		if rec := h.c.do("PUT", "/api/provisioning/targets/"+h.conn, `{"kind":"scim","base_url":"`+h.url+`","rest":{},"token":"t"}`); rec.Code != 422 {
			t.Errorf("rest on a SCIM target: %d", rec.Code)
		}
		put(f.URL, spec, `{"password":"p"}`, 422) // a credential that does not fit the auth type
	})

	t.Run("saved without secrets, base url or write-back", func(t *testing.T) {
		out := put(f.URL, spec, fakerest.ClientSecret, 200)
		if out["kind"] != "rest" || out["has_credential"] != true || out["write_back"] != false || out["base_url"] != f.URL {
			t.Fatalf("view = %v", out)
		}
		raw, _ := json.Marshal(out)
		if strings.Contains(string(raw), fakerest.ClientSecret) {
			t.Error("the view carries the credential")
		}
		rest, _ := json.Marshal(out["rest"])
		if strings.Contains(string(rest), "base_url") || !strings.Contains(string(rest), `"client_id":"client-1"`) {
			t.Errorf("stored spec = %s", rest)
		}
		if !strings.Contains(h.auditDetail(), "rest") {
			t.Errorf("audit = %s", h.auditDetail())
		}
	})

	t.Run("dry run shows the exact writes and sends none", func(t *testing.T) {
		out := h.c.json("POST", "/api/provisioning/targets/"+h.conn+"/dry-run",
			`{"kind":"create_account","username":"new/user","email":"n@example.com"}`, 200).(map[string]any)
		steps, _ := out["steps"].([]any)
		var writes []map[string]any
		var sentGets int
		for _, s := range steps {
			m := s.(map[string]any)
			switch {
			case m["sent"] == true && m["method"] == "GET":
				sentGets++
			case m["sent"] == false:
				writes = append(writes, m)
			}
		}
		if out["error"] != "" || len(writes) != 1 || writes[0]["method"] != "POST" || sentGets < 1 {
			t.Fatalf("dry run = %v", out)
		}
		if body := writes[0]["body"].(string); body != `{"email":"n@example.com","login":"new/user"}` {
			t.Errorf("body = %s", body)
		}
		for _, r := range f.APIRequests() {
			if r.Method != "GET" {
				t.Errorf("the target received %s %s", r.Method, r.Path)
			}
		}
		if f.TokenCalls == 0 {
			t.Error("the OAuth token was not fetched, so the reads could not be authenticated")
		}
		if got := f.APIRequests()[0].Path; got != "/users/new%2Fuser" {
			t.Errorf("the lookup path = %q: the username was not escaped", got)
		}
		if raw, _ := json.Marshal(out); strings.Contains(string(raw), fakerest.ClientSecret) || strings.Contains(string(raw), fakerest.OAuthToken) {
			t.Error("the dry run carries a credential")
		}
	})

	t.Run("moving the target needs a new credential", func(t *testing.T) {
		g := fakerest.New(1)
		defer g.Close()
		out := put(g.URL, strings.Replace(restSpec, "%s", g.URL, 1), "", 422)
		if out["error"] != "credential_required" {
			t.Errorf("code = %v", out["error"])
		}
	})
}
