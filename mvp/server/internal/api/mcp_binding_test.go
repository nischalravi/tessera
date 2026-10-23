package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Binding of MCP resource servers to an issuer and audience, and the policy
// against unregistered servers, over HTTP (issue #479).
func TestMCP_ResourceBinding(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	view := func(id string) resourceView {
		var list []resourceView
		rec := corrDo(x.h, x.admin, "GET", "/api/mcp/resources", "")
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("list: %d %s", rec.Code, rec.Body)
		}
		for _, v := range list {
			if v.ID == id {
				return v
			}
		}
		t.Fatalf("resource %s not listed", id)
		return resourceView{}
	}
	// a resource with no explicit binding is bound to the defaults
	if v := view(x.resA.id); v.Bound || v.Issuer != x.issuer || v.Audience != x.resA.uri {
		t.Errorf("default binding = %+v", v)
	}
	// registration may bind it at once; the metadata advertises the bound issuer
	rec := corrDo(x.h, x.admin, "POST", "/api/mcp/resources",
		`{"resource":"https://mcp-c.example/mcp","name":"mcp c","issuer":"https://as.example/mcp","audience":"https://api.mcp-c.example/"}`)
	var c resourceView
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &c) != nil || !c.Bound || c.Issuer != "https://as.example/mcp" ||
		c.Audience != "https://api.mcp-c.example/" {
		t.Fatalf("create bound: %d %s", rec.Code, rec.Body)
	}
	if m := jsonBody(t, serve(x.h, httptest.NewRequest("GET", x.base+"/.well-known/oauth-protected-resource/"+c.ID, nil))); fmt.Sprint(m["authorization_servers"]) != "[https://as.example/mcp]" {
		t.Errorf("PRM = %v", m)
	}
	// validation
	for name, body := range map[string]string{
		"issuer without audience": `{"issuer":"https://as.example/mcp"}`,
		"audience without issuer": `{"audience":"https://api.example/"}`,
		"http issuer":             `{"issuer":"http://as.example/","audience":"https://api.example/"}`,
		"issuer with a query":     `{"issuer":"https://as.example/?a=1","audience":"https://api.example/"}`,
		"audience not a URI":      `{"issuer":"https://as.example/","audience":"mcp-a"}`,
		"nothing":                 `{}`,
		"unknown field":           `{"status":"active","x":1}`,
	} {
		if rec := corrDo(x.h, x.admin, "PUT", "/api/mcp/resources/"+x.resA.id, body); rec.Code != 422 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// the audience of one server is never the audience of another
	if rec := corrDo(x.h, x.admin, "PUT", "/api/mcp/resources/"+x.resA.id, fmt.Sprintf(`{"issuer":%q,"audience":%q}`, x.issuer, x.resB.uri)); rec.Code != 409 {
		t.Errorf("audience of B: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(x.h, x.admin, "PUT", "/api/mcp/resources/"+x.resA.id, `{"issuer":"https://as.example/mcp","audience":"https://api.mcp-c.example/"}`); rec.Code != 409 {
		t.Errorf("audience of C: %d %s", rec.Code, rec.Body)
	}
	// only a policy admin binds
	if rec := corrDo(x.h, x.alice, "PUT", "/api/mcp/resources/"+x.resA.id, fmt.Sprintf(`{"issuer":%q,"audience":"https://a.example/"}`, x.issuer)); rec.Code != 403 {
		t.Errorf("bind as a viewer: %d", rec.Code)
	}
	otherAdmin := signIn(t, x.f.DB, x.other.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	// another tenant's admin cannot reach the resource
	if rec := corrDo(x.h, otherAdmin, "PUT", "/api/mcp/resources/"+x.resA.id, fmt.Sprintf(`{"issuer":%q,"audience":"https://a.example/"}`, x.issuer)); rec.Code != 404 {
		t.Errorf("bind in another tenant: %d", rec.Code)
	}

	// a token issued under the default binding...
	tok := x.userToken(x.resA)["access_token"].(string)
	if jsonBody(t, x.introspect(tok, x.resA))["active"] != true {
		t.Fatal("token not active")
	}
	// ...is revoked when the audience changes, and the new token carries it
	rec = corrDo(x.h, x.admin, "PUT", "/api/mcp/resources/"+x.resA.id, fmt.Sprintf(`{"issuer":%q,"audience":"https://api.mcp-a.example/"}`, x.issuer))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"bound":true`) {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body)
	}
	if got := jsonBody(t, x.introspect(tok, x.resA))["active"]; got != false {
		t.Errorf("a token of the old binding is still active: %v", got)
	}
	tok = x.userToken(x.resA)["access_token"].(string)
	if in := jsonBody(t, x.introspect(tok, x.resA)); in["active"] != true || in["aud"] != "https://api.mcp-a.example/" {
		t.Errorf("introspect under the new binding = %v", in)
	}
	if jsonBody(t, x.introspect(tok, x.resB))["active"] != false {
		t.Error("A's token is active at B")
	}

	// bound to another authorization server: no token is issued for it, and
	// the token it had is refused
	rec = corrDo(x.h, x.admin, "PUT", "/api/mcp/resources/"+x.resA.id, `{"issuer":"https://other-as.example/mcp","audience":"https://api.mcp-a.example/"}`)
	if rec.Code != 200 {
		t.Fatalf("rebind: %d %s", rec.Code, rec.Body)
	}
	rec = serve(x.h, authed(x.alice, "GET", x.authorizeURL(nil), ""))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc == nil || mcpQueryOf(loc).Get("error") != "invalid_target" ||
		!strings.Contains(mcpQueryOf(loc).Get("error_description"), "bound to another authorization server") {
		t.Errorf("authorize for a resource bound elsewhere: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if jsonBody(t, x.introspect(tok, x.resA))["active"] != false {
		t.Error("a token of the old issuer is still active")
	}

	// the policy: an unregistered or disabled MCP server gets no token
	rec = serve(x.h, authed(x.alice, "GET", x.authorizeURL(func(q url.Values) { q.Set("resource", "https://rogue.example/mcp") }), ""))
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc == nil || !strings.Contains(mcpQueryOf(loc).Get("error_description"), "blocked by policy") {
		t.Errorf("unregistered server: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	var n int
	if err := x.f.DB.ReadTenant(t.Context(), x.main.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{Action: "mcp.policy.unregistered_server"})
		n = len(evs)
		return err
	}); err != nil || n != 1 {
		t.Errorf("policy denials audited = %d, %v", n, err)
	}
}
