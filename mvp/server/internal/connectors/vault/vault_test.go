package vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vault"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const token = "hvs.CAESIJ-vault-token-secret"

type obj = map[string]any

const adminPolicy = `
# platform admins
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/data/app/*" { # trailing comment
  capabilities = ["read", "list"]
  allowed_parameters = { "foo" = ["a", "b"] }
}
/* block comment path "ignored/*" { capabilities = ["sudo"] } */
path "sys/health" {
  capabilities = ["read"]
}
`

// fake is an in-process Vault: token check, GET with list=true for a list, 404 for an empty list.
type fake struct {
	docs  map[string]any      // path -> data
	lists map[string][]string // path -> keys
	deny  map[string]bool     // path -> answer 403
	ns    string
}

func newFake() *fake {
	f := &fake{docs: map[string]any{}, lists: map[string][]string{}, deny: map[string]bool{}}
	f.lists["sys/policies/acl"] = []string{"admin", "app-read", "default", "root", "weird"}
	f.docs["sys/policies/acl/admin"] = obj{"policy": adminPolicy}
	f.docs["sys/policies/acl/app-read"] = obj{"policy": `path "secret/data/app/*" { capabilities = ["read"] }
path "secret/data/deny/*" { capabilities = ["deny", "delete"] }`}
	f.docs["sys/policies/acl/default"] = obj{"policy": `path "auth/token/lookup-self" { capabilities = ["read"] }`}
	f.docs["sys/policies/acl/weird"] = obj{"policy": `path "x" { capabilities = ["read"] `}
	f.docs["sys/auth"] = obj{
		"approle/":  obj{"type": "approle"},
		"k8s/":      obj{"type": "kubernetes"},
		"ldap/":     obj{"type": "ldap"},
		"token/":    obj{"type": "token"},
		"userpass/": obj{"type": "userpass"},
		"oidc/":     obj{"type": "oidc"},
		"github/":   obj{"type": "github"}, // no collection read for this type
	}
	f.lists["auth/approle/role"] = []string{"ci", "gone"}
	f.docs["auth/approle/role/ci"] = obj{"token_policies": []string{"app-read", "nope"}, "secret_id_ttl": 0}
	f.lists["auth/k8s/role"] = []string{"web"}
	f.docs["auth/k8s/role/web"] = obj{"policies": []string{"default"}, "token_policies": []string{"app-read"}, "bound_service_account_names": []string{"web"}}
	f.lists["auth/ldap/users"] = []string{"ada"}
	f.docs["auth/ldap/users/ada"] = obj{"policies": []string{"default"}, "groups": []string{"ops", "ghost"}}
	f.lists["auth/ldap/groups"] = []string{"ops"}
	f.docs["auth/ldap/groups/ops"] = obj{"policies": []string{"admin"}}
	f.lists["auth/token/roles"] = []string{"batch"}
	f.docs["auth/token/roles/batch"] = obj{"allowed_policies": []string{"app-read"}}
	f.lists["auth/userpass/users"] = []string{"bob"}
	f.docs["auth/userpass/users/bob"] = obj{"token_policies": []string{"default"}}
	f.deny["auth/oidc/role"] = true
	f.lists["identity/entity/id"] = []string{"11111111-aaaa", "22222222-bbbb", "33333333-cccc"}
	f.docs["identity/entity/id/11111111-aaaa"] = obj{"id": "11111111-aaaa", "name": "ada", "policies": []string{"admin"}, "group_ids": []string{"g1"},
		"metadata": obj{"email": "Ada@Acme.example"}, "aliases": []obj{{"mount_type": "ldap"}}}
	f.docs["identity/entity/id/22222222-bbbb"] = obj{"id": "22222222-bbbb", "name": "ci-bot", "policies": []string{"app-read"}, "disabled": true,
		"aliases": []obj{{"mount_type": "approle"}, {"mount_type": "kubernetes"}}}
	f.docs["identity/entity/id/33333333-cccc"] = obj{"id": "33333333-cccc", "name": "mixed", "aliases": []obj{{"mount_type": "approle"}, {"mount_type": "oidc"}}}
	f.lists["identity/group/id"] = []string{"g1", "g2"}
	f.docs["identity/group/id/g1"] = obj{"id": "g1", "name": "platform", "policies": []string{"admin"}, "member_entity_ids": []string{"11111111-aaaa", "ffffffff-dead"}}
	f.docs["identity/group/id/g2"] = obj{"id": "g2", "name": "everyone", "policies": []string{"default"}, "member_group_ids": []string{"g1"}}
	return f
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("X-Vault-Token") != token {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	if f.ns != "" && r.Header.Get("X-Vault-Namespace") != f.ns {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/v1/") {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	if f.deny[p] {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	switch {
	case r.URL.Query().Get("list") == "true":
		keys, ok := f.lists[p]
		if !ok || len(keys) == 0 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(obj{"data": obj{"keys": keys}})
	case p == "auth/token/lookup-self":
		_ = json.NewEncoder(w).Encode(obj{"data": obj{"display_name": "token-tessera", "id": token}})
	default:
		d, ok := f.docs[p]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(obj{"data": d})
	}
}

func open(t *testing.T, f *fake, cfg vault.Config) (*connsynctest.Server, *vault.Client) {
	t.Helper()
	srv := connsynctest.New(t, f)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	cfg.BaseURL, cfg.Token = srv.URL, connsync.NewSecret(token)
	c, err := vault.Open(cfg, connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func discover(t *testing.T, c *vault.Client) *connectors.DiscoveryResult {
	t.Helper()
	res, err := vault.NewConnector(c).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hasEdge(res *connectors.DiscoveryResult, srcKind, src, rel, dst string) bool {
	return slices.ContainsFunc(res.Edges, func(e connectors.EdgeRecord) bool {
		return e.Src.Kind == srcKind && e.Src.ExternalID == src && e.Relation == rel && e.Dst.ExternalID == dst
	})
}

func TestDiscoverMapsPoliciesRolesEntitiesAndGroups(t *testing.T) {
	f := newFake()
	srv, c := open(t, f, vault.Config{})
	res := discover(t, c)
	if res.System != "vault" {
		t.Errorf("system %q", res.System)
	}
	if !strings.Contains(res.Partial, "a policy could not be parsed") || !strings.Contains(res.Partial, "an auth method could not be listed") {
		t.Errorf("partial %q", res.Partial)
	}
	groups := map[string]connectors.GroupRecord{}
	for _, g := range res.Groups {
		groups[g.ExternalID] = g
	}
	for id, priv := range map[string]bool{"policy:admin": true, "policy:root": true, "policy:app-read": false, "policy:default": false, "policy:weird": false} {
		if g, ok := groups[id]; !ok || g.Privileged != priv || g.Kind != vault.KindPolicy {
			t.Errorf("%s: %+v (present %v), want privileged %v", id, g, ok, priv)
		}
	}
	perms := map[string]connectors.PermissionRecord{}
	for _, p := range res.Permissions {
		perms[p.ExternalID] = p
	}
	if p := perms["policy:admin|sys/policies/acl/*"]; !p.Privileged || p.Action != "create,read,update,delete,list" {
		t.Errorf("admin sys permission %+v", p)
	}
	if p := perms["policy:admin|secret/data/app/*"]; p.Privileged || p.Action != "read,list" {
		t.Errorf("admin secret permission %+v", p)
	}
	if _, ok := perms["policy:admin|ignored/*"]; ok {
		t.Error("a commented-out block was read")
	}
	if p := perms["policy:app-read|secret/data/deny/*"]; p.Privileged {
		t.Errorf("a deny block is privileged: %+v", p)
	}
	for _, e := range []struct{ kind, src, rel, dst string }{
		{"group", "policy:admin", "grants", "policy:admin|sys/policies/acl/*"},
		{"account", "role:approle/ci", "member_of", "policy:app-read"},
		{"account", "role:k8s/web", "member_of", "policy:default"},
		{"account", "role:k8s/web", "member_of", "policy:app-read"},
		{"account", "role:token/batch", "member_of", "policy:app-read"},
		{"account", "user:ldap/ada", "member_of", "ldapgroup:ldap/ops"},
		{"group", "ldapgroup:ldap/ops", "member_of", "policy:admin"},
		{"account", "user:userpass/bob", "member_of", "policy:default"},
		{"account", "entity:11111111-aaaa", "member_of", "policy:admin"},
		{"account", "entity:11111111-aaaa", "member_of", "idgroup:g1"},
		{"group", "idgroup:g1", "member_of", "policy:admin"},
		{"group", "idgroup:g2", "member_of", "idgroup:g1"},
	} {
		if !hasEdge(res, e.kind, e.src, e.rel, e.dst) {
			t.Errorf("missing edge %+v", e)
		}
	}
	for _, e := range res.Edges { // no dangling ends: a policy that does not exist, an LDAP group nobody listed, an unread entity
		if strings.Contains(e.Dst.ExternalID, "nope") || strings.Contains(e.Dst.ExternalID, "ghost") || strings.Contains(e.Src.ExternalID, "ffffffff") {
			t.Errorf("dangling edge %+v", e)
		}
	}
	accts := map[string]connectors.AccountRecord{}
	for _, a := range res.Accounts {
		accts[a.ExternalID] = a
	}
	if a := accts["role:approle/ci"]; a.Kind != "service" || a.Attributes["auth_type"] != "approle" {
		t.Errorf("approle role %+v", a)
	}
	if a := accts["entity:11111111-aaaa"]; a.Kind != "user" || a.Identity == nil || a.Identity.Email != "ada@acme.example" {
		t.Errorf("ada entity %+v", a)
	}
	if a := accts["entity:22222222-bbbb"]; a.Kind != "service" || a.Status != "disabled" {
		t.Errorf("bot entity %+v", a)
	}
	if a := accts["entity:33333333-cccc"]; a.Kind != "user" {
		t.Errorf("mixed-alias entity is %q", a.Kind)
	}
	// nothing outside the fixed read paths, never a write, and the token on every call
	for _, r := range srv.Requests() {
		if r.Method != http.MethodGet {
			t.Errorf("non-read request %s %s", r.Method, r.Path)
		}
		if strings.Contains(r.Path, "/secret/") && !strings.HasPrefix(r.Path, "/v1/sys/") {
			t.Errorf("a secret engine path was requested: %s", r.Path)
		}
	}
	if srv.Count("/v1/sys/policies/acl/root") != 0 {
		t.Error("the root policy was read")
	}
	if srv.Count("/v1/auth/github") != 0 {
		t.Error("an auth type without a known collection was read")
	}
}

func TestNamespaceHeader(t *testing.T) {
	f := newFake()
	f.ns = "team-a/prod"
	_, c := open(t, f, vault.Config{Namespace: "team-a/prod"})
	if _, err := c.Probe(context.Background()); err != nil {
		t.Errorf("probe with the namespace: %v", err)
	}
	_, c = open(t, f, vault.Config{})
	if _, err := c.Probe(context.Background()); connsync.Status(err) != http.StatusForbidden {
		t.Errorf("probe without the namespace: %v", err)
	}
}

func TestProbeAndDeniedToken(t *testing.T) {
	_, c := open(t, newFake(), vault.Config{})
	r, err := c.Probe(context.Background())
	if err != nil || r.Identity != "token-tessera" || r.Policies != 5 || r.AuthMethods != 7 || r.Entities != 3 {
		t.Errorf("probe %+v, %v", r, err)
	}
	if strings.Contains(fmt.Sprint(r), token) {
		t.Error("the probe result holds the token")
	}
	srv := connsynctest.New(t, newFake())
	hc, _ := safehttp.NewForTest(t, srv.Options(0))
	bad, err := vault.Open(vault.Config{BaseURL: srv.URL, Token: connsync.NewSecret("hvs.wrong-token")}, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bad.Probe(context.Background())
	if connsync.Status(err) != http.StatusForbidden || strings.Contains(err.Error(), "hvs.wrong-token") {
		t.Errorf("wrong token: %v", err)
	}
	// a token that cannot list policies fails the read: that class is the connector's purpose
	f := newFake()
	f.deny["sys/policies/acl"] = true
	_, c = open(t, f, vault.Config{})
	if _, err := vault.NewConnector(c).Discover(context.Background()); err == nil {
		t.Error("discover succeeded without the policy list")
	}
}

func TestEmptyListIsNotAnError(t *testing.T) {
	f := newFake()
	f.lists["identity/entity/id"] = nil
	f.lists["identity/group/id"] = nil
	_, c := open(t, f, vault.Config{})
	res := discover(t, c)
	for _, a := range res.Accounts {
		if strings.HasPrefix(a.ExternalID, "entity:") {
			t.Errorf("entity %s from an empty list", a.ExternalID)
		}
	}
}

func TestPathElementsFromResponsesCannotEscape(t *testing.T) {
	f := newFake()
	f.lists["auth/approle/role"] = []string{"..", "a%2Fb", "ok"}
	f.docs["auth/approle/role/ok"] = obj{"token_policies": []string{"default"}}
	srv, c := open(t, f, vault.Config{})
	res := discover(t, c)
	for _, r := range srv.Requests() {
		if strings.Contains(r.Path, "..") {
			t.Errorf("request path %s", r.Path)
		}
	}
	if !slices.ContainsFunc(res.Accounts, func(a connectors.AccountRecord) bool { return a.ExternalID == "role:approle/ok" }) {
		t.Error("the valid role was not read")
	}
}

func TestParsePolicy(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []vault.PathRule
		err       bool
	}{
		{"hcl", `path "a/*" { capabilities = ["read","list"] }`, []vault.PathRule{{Path: "a/*", Capabilities: []string{"read", "list"}}}, false},
		{"nested braces and comments", "# c\npath \"b\" {\n  allowed_parameters = { \"k\" = [] } // x\n  capabilities = [\"update\"]\n}\n", []vault.PathRule{{Path: "b", Capabilities: []string{"update"}}}, false},
		{"unknown capability dropped", `path "c" { capabilities = ["read","teleport"] }`, []vault.PathRule{{Path: "c", Capabilities: []string{"read"}}}, false},
		{"hash inside a string is not a comment", `path "d#e" { capabilities = ["read"] }`, []vault.PathRule{{Path: "d#e", Capabilities: []string{"read"}}}, false},
		{"json", `{"path":{"j/*":{"capabilities":["sudo"]}}}`, []vault.PathRule{{Path: "j/*", Capabilities: []string{"sudo"}}}, false},
		{"unbalanced", `path "x" { capabilities = ["read"]`, nil, true},
		{"bad json", `{"path":`, nil, true},
		{"empty", ``, nil, false},
	} {
		got, err := vault.ParsePolicy(c.src)
		if (err != nil) != c.err {
			t.Errorf("%s: err %v", c.name, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: %+v", c.name, got)
			continue
		}
		for i := range got {
			if got[i].Path != c.want[i].Path || !slices.Equal(got[i].Capabilities, c.want[i].Capabilities) {
				t.Errorf("%s: %+v, want %+v", c.name, got[i], c.want[i])
			}
		}
	}
	huge := strings.Repeat("path \"p\" { capabilities = [\"read\"] }\n", 2001)
	if _, err := vault.ParsePolicy(huge); err == nil {
		t.Error("a policy with 2001 blocks was read")
	}
}

func TestRulePrivileged(t *testing.T) {
	for _, c := range []struct {
		path string
		caps []string
		want bool
	}{
		{"secret/data/x", []string{"sudo"}, true},
		{"sys/policies/acl/x", []string{"update"}, true},
		{"sys/mounts", []string{"read"}, false},
		{"auth/token/create", []string{"update"}, true},
		{"identity/entity/id/x", []string{"delete"}, true},
		{"*", []string{"create"}, true},
		{"+", []string{"read", "list"}, false},
		{"secret/data/x", []string{"create", "update"}, false},
		{"sys/x", []string{"deny", "sudo"}, false},
	} {
		if got := vault.RulePrivileged(vault.PathRule{Path: c.path, Capabilities: c.caps}); got != c.want {
			t.Errorf("%s %v: %v", c.path, c.caps, got)
		}
	}
}

func TestOpenValidationAndFromEnv(t *testing.T) {
	srv := connsynctest.New(t, newFake())
	hc, _ := safehttp.NewForTest(t, srv.Options(0))
	prod := connsync.Runtime{Env: config.Prod}
	ok := connsync.NewSecret("hvs.t")
	for _, c := range []struct {
		name string
		cfg  vault.Config
		rt   connsync.Runtime
		hc   *http.Client
	}{
		{"no client", vault.Config{BaseURL: srv.URL, Token: ok}, connsynctest.Runtime, nil},
		{"no token", vault.Config{BaseURL: srv.URL}, connsynctest.Runtime, hc},
		{"token with a newline", vault.Config{BaseURL: srv.URL, Token: connsync.NewSecret("a\nb")}, connsynctest.Runtime, hc},
		{"path", vault.Config{BaseURL: srv.URL + "/v1", Token: ok}, connsynctest.Runtime, hc},
		{"http in prod", vault.Config{BaseURL: "http://vault.example.com", Token: ok}, prod, hc},
		{"loopback in prod", vault.Config{BaseURL: srv.URL, Token: ok}, prod, hc},
		{"bad namespace", vault.Config{BaseURL: srv.URL, Token: ok, Namespace: "../x"}, connsynctest.Runtime, hc},
	} {
		if _, err := vault.Open(c.cfg, c.rt, c.hc, nil); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	env := map[string]string{"TESSERA_VAULT_BASE_URL": srv.URL, "TESSERA_VAULT_TOKEN": "env:V", "V": token, "TESSERA_VAULT_NAMESPACE": ""}
	getenv := func(k string) string { return env[k] }
	cn, err := vault.FromEnv(getenv, connsynctest.Runtime, hc, nil)
	if err != nil || cn.System() != "vault" {
		t.Fatalf("%v", err)
	}
	if _, err := cn.Discover(context.Background()); err != nil {
		t.Error(err)
	}
	env["V"] = ""
	if _, err := vault.FromEnv(getenv, connsynctest.Runtime, hc, nil); err == nil || strings.Contains(err.Error(), token) {
		t.Errorf("empty token reference: %v", err)
	}
	cfg := vault.Config{Token: connsync.NewSecret(token)}
	if s := fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg); strings.Contains(s, token) {
		t.Error("the config prints the token")
	}
}
