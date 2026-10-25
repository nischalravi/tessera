package kubernetes_test

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
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/kubernetes"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const token = "eyJhbGciOi-service-account-token"

type obj = map[string]any

func meta(ns, name string) obj {
	m := obj{"name": name}
	if ns != "" {
		m["namespace"] = ns
	}
	return obj{"metadata": m}
}

func with(o obj, k string, v any) obj { o[k] = v; return o }

func rules(verbs, resources string) []obj {
	return []obj{{"verbs": strings.Split(verbs, ","), "resources": strings.Split(resources, ","), "apiGroups": []string{""}}}
}

func rule(verbs, resources string) []kubernetes.Rule {
	return []kubernetes.Rule{{Verbs: strings.Split(verbs, ","), Resources: strings.Split(resources, ","), APIGroups: []string{""}}}
}

func binding(ns, name, kind, role string, subjects ...obj) obj {
	return with(with(meta(ns, name), "roleRef", obj{"kind": kind, "name": role}), "subjects", subjects)
}

// fake is an in-process Kubernetes API server: list endpoints with limit and continue, a bearer token check.
type fake struct {
	cluster   map[string][]obj // path -> items
	pageSize  int
	openshift bool
}

func newFake() *fake {
	f := &fake{pageSize: 2, cluster: map[string][]obj{}}
	rb := "/apis/rbac.authorization.k8s.io/v1/"
	f.cluster[rb+"clusterroles"] = []obj{
		with(meta("", "cluster-admin"), "rules", rules("*", "*")),
		with(meta("", "view"), "rules", rules("get,list", "pods,services")),
		with(meta("", "secret-reader"), "rules", rules("get", "secrets")),
		with(meta("", "rbac-writer"), "rules", rules("create", "rolebindings")),
	}
	f.cluster[rb+"clusterrolebindings"] = []obj{
		binding("", "admins", "ClusterRole", "cluster-admin", obj{"kind": "Group", "name": "oidc:platform"}, obj{"kind": "User", "name": "oidc:Ada@Acme.example"}),
		binding("", "sa-all", "ClusterRole", "view", obj{"kind": "Group", "name": "system:serviceaccounts"}),
	}
	f.cluster[rb+"roles"] = []obj{
		with(meta("payments", "deployer"), "rules", rules("update,patch", "deployments")),
		with(meta("payments", "exec"), "rules", rules("create", "pods/exec")),
	}
	f.cluster[rb+"rolebindings"] = []obj{
		binding("payments", "dep", "Role", "deployer", obj{"kind": "ServiceAccount", "name": "ci", "namespace": "payments"}, obj{"kind": "User", "name": "bob"}),
		binding("payments", "ex", "Role", "exec", obj{"kind": "ServiceAccount", "name": "debug"}),
		binding("payments", "sr", "ClusterRole", "secret-reader", obj{"kind": "Group", "name": "oidc:payments-ro"}),
		binding("web", "v", "ClusterRole", "view", obj{"kind": "User", "name": "bob"}),
		binding("web", "dangling", "Role", "gone", obj{"kind": "User", "name": "zed"}),
	}
	f.cluster["/api/v1/serviceaccounts"] = []obj{meta("payments", "ci"), meta("payments", "debug"), meta("web", "default"), meta("Bad NS", "x")}
	f.cluster["/apis/user.openshift.io/v1/groups"] = []obj{
		with(meta("", "oidc:platform"), "users", []string{"ada", "bob"}),
		with(meta("", "ops"), "users", []string{"carol"}),
	}
	return f
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","message":"Unauthorized"}`))
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Path
	items, ok := f.cluster[path]
	if !ok {
		// /api/v1/namespaces/NS/serviceaccounts and the rbac namespaced forms
		if i := strings.Index(path, "/namespaces/"); i >= 0 {
			rest := strings.SplitN(path[i+len("/namespaces/"):], "/", 2)
			if len(rest) == 2 {
				for _, it := range f.cluster[path[:i]+"/"+rest[1]] {
					if it["metadata"].(obj)["namespace"] == rest[0] {
						items = append(items, it)
					}
				}
				ok = true
			}
		}
	}
	if !ok || (strings.Contains(path, "openshift") && !f.openshift) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	size := f.pageSize
	if l := r.URL.Query().Get("limit"); l == "5" {
		size = 5
	}
	start := 0
	if c := r.URL.Query().Get("continue"); c != "" {
		for i := range items {
			if c == "c"+string(rune('0'+i)) {
				start = i
			}
		}
	}
	end := min(start+size, len(items))
	md := obj{}
	if end < len(items) {
		md["continue"] = "c" + string(rune('0'+end))
	}
	_ = json.NewEncoder(w).Encode(obj{"metadata": md, "items": items[start:end]})
}

func open(t *testing.T, f *fake, cfg kubernetes.Config) (*connsynctest.Server, *kubernetes.Client) {
	t.Helper()
	srv := connsynctest.New(t, f)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	cfg.BaseURL, cfg.Token = srv.URL, connsync.NewSecret(token)
	c, err := kubernetes.Open(cfg, connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func discover(t *testing.T, c *kubernetes.Client) *connectors.DiscoveryResult {
	t.Helper()
	res, err := kubernetes.NewConnector(c).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func perms(res *connectors.DiscoveryResult) map[string]bool {
	m := map[string]bool{}
	for _, p := range res.Permissions {
		m[p.ExternalID] = p.Privileged
	}
	return m
}

func hasEdge(res *connectors.DiscoveryResult, srcKind, src, rel, dst string) bool {
	return slices.ContainsFunc(res.Edges, func(e connectors.EdgeRecord) bool {
		return e.Src.Kind == srcKind && e.Src.ExternalID == src && e.Relation == rel && e.Dst.ExternalID == dst
	})
}

func TestDiscoverMapsRolesBindingsAndServiceAccounts(t *testing.T) {
	_, c := open(t, newFake(), kubernetes.Config{})
	res := discover(t, c)
	if res.System != "kubernetes" || res.Partial != "" {
		t.Fatalf("system %q partial %q", res.System, res.Partial)
	}
	want := map[string]bool{
		"cluster|clusterrole:cluster-admin":            true,
		"cluster|clusterrole:view":                     false,
		"namespace:payments|role:deployer":             false,
		"namespace:payments|role:exec":                 true,
		"namespace:payments|clusterrole:secret-reader": true,
		"namespace:web|clusterrole:view":               false,
		"namespace:web|role:gone":                      false,
	}
	got := perms(res)
	for id, priv := range want {
		if p, ok := got[id]; !ok || p != priv {
			t.Errorf("permission %s: present %v privileged %v, want privileged %v", id, ok, p, priv)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d permissions, want %d: %v", len(got), len(want), got)
	}
	for _, e := range []struct{ kind, src, rel, dst string }{
		{"group", "group:oidc:platform", "grants", "cluster|clusterrole:cluster-admin"},
		{"account", "user:oidc:Ada@Acme.example", "direct_grant", "cluster|clusterrole:cluster-admin"},
		{"account", "sa:payments/ci", "direct_grant", "namespace:payments|role:deployer"},
		{"account", "sa:payments/debug", "direct_grant", "namespace:payments|role:exec"}, // namespace defaults to the binding's
		{"group", "group:oidc:payments-ro", "grants", "namespace:payments|clusterrole:secret-reader"},
		{"account", "sa:web/default", "member_of", "group:system:serviceaccounts"},
		{"account", "sa:payments/ci", "member_of", "group:system:serviceaccounts"},
	} {
		if !hasEdge(res, e.kind, e.src, e.rel, e.dst) {
			t.Errorf("missing edge %+v", e)
		}
	}
	accts := map[string]connectors.AccountRecord{}
	for _, a := range res.Accounts {
		accts[a.ExternalID] = a
	}
	if a := accts["sa:web/default"]; a.Kind != "service" {
		t.Errorf("service account kind %q", a.Kind)
	}
	if a := accts["user:oidc:Ada@Acme.example"]; a.Kind != "user" || a.Identity == nil || a.Identity.Email != "ada@acme.example" {
		t.Errorf("user account %+v", a)
	}
	if _, bad := accts["sa:Bad NS/x"]; bad {
		t.Error("a service account in an invalid namespace was kept")
	}
	for _, g := range res.Groups {
		if g.Kind == kubernetes.KindOpenShift {
			t.Errorf("group %s is an OpenShift group without OpenShift", g.ExternalID)
		}
	}
	if !slices.ContainsFunc(res.Resources, func(r connectors.ResourceRecord) bool {
		return r.ExternalID == "namespace:payments" && r.Kind == kubernetes.KindNamespace
	}) {
		t.Error("no namespace resource")
	}
}

func TestDiscoverOpenShiftGroups(t *testing.T) {
	f := newFake()
	f.openshift = true
	_, c := open(t, f, kubernetes.Config{OpenShift: true})
	res := discover(t, c)
	kinds := map[string]string{}
	for _, g := range res.Groups {
		kinds[g.ExternalID] = g.Kind
	}
	if kinds["group:oidc:platform"] != kubernetes.KindOpenShift || kinds["group:ops"] != kubernetes.KindOpenShift || kinds["group:oidc:payments-ro"] != kubernetes.KindGroup {
		t.Errorf("group kinds %v", kinds)
	}
	if !hasEdge(res, "account", "user:ada", "member_of", "group:oidc:platform") || !hasEdge(res, "account", "user:carol", "member_of", "group:ops") {
		t.Error("OpenShift group members are not member_of edges")
	}
	// without the setting the OpenShift API is not called, and a plain cluster has none
	srv, plain := open(t, newFake(), kubernetes.Config{})
	discover(t, plain)
	if srv.Count("/apis/user.openshift.io") != 0 {
		t.Error("OpenShift groups were requested without the setting")
	}
	_, broken := open(t, newFake(), kubernetes.Config{OpenShift: true})
	if _, err := kubernetes.NewConnector(broken).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "OpenShift groups") {
		t.Errorf("OpenShift on a plain cluster: %v", err)
	}
}

func TestNamespacesRestrictTheNamespacedReads(t *testing.T) {
	srv, c := open(t, newFake(), kubernetes.Config{Namespaces: []string{"payments"}})
	res := discover(t, c)
	if srv.Count("/apis/rbac.authorization.k8s.io/v1/roles") != 0 || srv.Count("/apis/rbac.authorization.k8s.io/v1/namespaces/payments/roles") == 0 {
		t.Errorf("requests %v", srv.Requests())
	}
	if _, ok := perms(res)["namespace:web|clusterrole:view"]; ok {
		t.Error("a binding of a namespace outside the list was read")
	}
	if _, ok := perms(res)["namespace:payments|role:exec"]; !ok {
		t.Error("a binding of the listed namespace was not read")
	}
}

func TestPaginationFollowsTheContinueTokenOnFixedPaths(t *testing.T) {
	f := newFake()
	srv, c := open(t, f, kubernetes.Config{})
	discover(t, c)
	if n := srv.Count("/apis/rbac.authorization.k8s.io/v1/rolebindings"); n != 3 { // five items, two per page
		t.Errorf("%d role binding pages, want 3", n)
	}
	for _, r := range srv.Requests() {
		if r.Method != http.MethodGet {
			t.Errorf("non-read request %s %s", r.Method, r.Path)
		}
		if r.Authorization != "Bearer "+token {
			t.Errorf("request without the token: %s", r.Path)
		}
	}
}

func TestProbeAndAuthFailure(t *testing.T) {
	f := newFake()
	f.openshift = true
	_, c := open(t, f, kubernetes.Config{OpenShift: true})
	r, err := c.Probe(context.Background())
	if err != nil || r.ClusterRoles != 4 || r.ClusterRoleBindings != 2 || r.ServiceAccounts != 4 || r.Groups != 2 {
		t.Errorf("probe %+v, %v", r, err)
	}
	if c.Mode() != "bearer_token" || c.Identity() == "" {
		t.Errorf("mode %q identity %q", c.Mode(), c.Identity())
	}
	srv := connsynctest.New(t, newFake())
	hc, _ := safehttp.NewForTest(t, srv.Options(0))
	bad, err := kubernetes.Open(kubernetes.Config{BaseURL: srv.URL, Token: connsync.NewSecret("wrong-token")}, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bad.Probe(context.Background())
	if connsync.Status(err) != http.StatusUnauthorized {
		t.Errorf("wrong token: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "wrong-token") {
		t.Error("the error repeats the token")
	}
}

func TestOpenValidation(t *testing.T) {
	srv := connsynctest.New(t, newFake())
	hc, _ := safehttp.NewForTest(t, srv.Options(0))
	prod := connsync.Runtime{Env: config.Prod}
	for _, c := range []struct {
		name string
		cfg  kubernetes.Config
		rt   connsync.Runtime
		hc   bool
	}{
		{"no client", kubernetes.Config{BaseURL: srv.URL, Token: connsync.NewSecret("t")}, connsynctest.Runtime, false},
		{"no token", kubernetes.Config{BaseURL: srv.URL}, connsynctest.Runtime, true},
		{"token with a space", kubernetes.Config{BaseURL: srv.URL, Token: connsync.NewSecret("a b")}, connsynctest.Runtime, true},
		{"path in the base URL", kubernetes.Config{BaseURL: srv.URL + "/x", Token: connsync.NewSecret("t")}, connsynctest.Runtime, true},
		{"http in prod", kubernetes.Config{BaseURL: "http://api.example.com", Token: connsync.NewSecret("t")}, prod, true},
		{"loopback in prod", kubernetes.Config{BaseURL: srv.URL, Token: connsync.NewSecret("t")}, prod, true},
		{"bad namespace", kubernetes.Config{BaseURL: srv.URL, Token: connsync.NewSecret("t"), Namespaces: []string{"../x"}}, connsynctest.Runtime, true},
		{"too many namespaces", kubernetes.Config{BaseURL: srv.URL, Token: connsync.NewSecret("t"), Namespaces: slices.Repeat([]string{"a"}, 101)}, connsynctest.Runtime, true},
	} {
		var h *http.Client
		if c.hc {
			h = hc
		}
		if _, err := kubernetes.Open(c.cfg, c.rt, h, nil); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestFromEnv(t *testing.T) {
	srv, _ := open(t, newFake(), kubernetes.Config{})
	hc, _ := safehttp.NewForTest(t, srv.Options(0))
	env := map[string]string{"TESSERA_KUBERNETES_BASE_URL": srv.URL, "TESSERA_KUBERNETES_TOKEN": "env:K", "K": token,
		"TESSERA_KUBERNETES_NAMESPACES": "payments, web", "TESSERA_KUBERNETES_OPENSHIFT": "false"}
	getenv := func(k string) string { return env[k] }
	cn, err := kubernetes.FromEnv(getenv, connsynctest.Runtime, hc, nil)
	if err != nil || cn.System() != "kubernetes" {
		t.Fatalf("%v", err)
	}
	if _, err := cn.Discover(context.Background()); err != nil {
		t.Error(err)
	}
	env["K"] = ""
	if _, err := kubernetes.FromEnv(getenv, connsynctest.Runtime, hc, nil); err == nil || strings.Contains(err.Error(), token) {
		t.Errorf("empty token reference: %v", err)
	}
	if s := (kubernetes.Config{Token: connsync.NewSecret(token)}); strings.Contains(fmt.Sprintf("%v %+v %#v", s, s, s), token) {
		t.Error("the config prints the token")
	}
}

func TestPrivilegedRules(t *testing.T) {
	for _, c := range []struct {
		name  string
		verbs string
		res   string
		want  bool
	}{
		{"cluster-admin", "*", "*", true},
		{"read secrets", "get", "secrets", true},
		{"read everything", "list", "*", true},
		{"impersonate", "impersonate", "users", true},
		{"escalate", "escalate", "clusterroles", true},
		{"write rolebindings", "create", "rolebindings", true},
		{"exec", "create", "pods/exec", true},
		{"mint tokens", "create", "serviceaccounts/token", true},
		{"read pods", "get,list,watch", "pods", false},
		{"update deployments", "update,patch", "deployments", false},
		{"read rolebindings", "get,list", "rolebindings", false},
	} {
		if got := kubernetes.Privileged(rule(c.verbs, c.res)); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	if kubernetes.Privileged([]kubernetes.Rule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}}}) {
		t.Error("a non-resource rule is privileged")
	}
}
