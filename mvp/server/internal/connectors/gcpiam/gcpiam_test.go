package gcpiam_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/gcpiam"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const saEmail = "tessera-reader@sec-proj-123.iam.gserviceaccount.com"

var t0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	js, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": saEmail, "private_key_id": "kid1",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": "https://oauth2.googleapis.com/token"})
	return k, string(js)
}

type fake struct {
	pub     *rsa.PublicKey
	deny    map[string]int
	evilIAM bool
	tokens  int
	bodies  []string
}

func (f *fake) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		if r.URL.Path == "/token" {
			f.tokenEndpoint(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			w.WriteHeader(401)
			return
		}
		for p, st := range f.deny {
			if strings.HasPrefix(r.URL.Path, p) {
				w.WriteHeader(st)
				write(map[string]any{"error": map[string]any{"code": st, "errors": []any{map[string]any{"reason": "forbidden"}}}})
				return
			}
		}
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/v3/folders":
			if q.Get("parent") == "organizations/123" {
				write(map[string]any{"folders": []any{map[string]any{"name": "folders/1000", "displayName": "Eng", "state": "ACTIVE"},
					map[string]any{"name": "folders/2000", "displayName": "Gone", "state": "DELETE_REQUESTED"}}})
				return
			}
			write(map[string]any{})
		case r.URL.Path == "/v3/projects":
			switch q.Get("parent") {
			case "organizations/123":
				if q.Get("pageToken") == "" {
					write(map[string]any{"projects": []any{map[string]any{"projectId": "alpha-proj-1", "displayName": "Alpha", "state": "ACTIVE"}}, "nextPageToken": "p2"})
					return
				}
				write(map[string]any{"projects": []any{map[string]any{"projectId": "sec-proj-123", "state": "ACTIVE"}}})
			case "folders/1000":
				write(map[string]any{"projects": []any{map[string]any{"projectId": "beta-proj-22", "state": "ACTIVE"}}})
			default:
				write(map[string]any{})
			}
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			b, _ := io.ReadAll(r.Body)
			f.bodies = append(f.bodies, string(b))
			if r.Method != http.MethodPost || !strings.Contains(string(b), `"requestedPolicyVersion":3`) {
				w.WriteHeader(400)
				return
			}
			write(policies[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v3/"), ":getIamPolicy")])
		case strings.HasPrefix(r.URL.Path, "/v1/roles/") || strings.Contains(r.URL.Path, "/roles/"):
			switch strings.TrimPrefix(r.URL.Path, "/v1/") {
			case "roles/owner":
				write(map[string]any{"name": "roles/owner", "title": "Owner", "includedPermissions": []string{"resourcemanager.projects.setIamPolicy", "storage.objects.get"}})
			case "roles/storage.objectViewer":
				write(map[string]any{"name": "roles/storage.objectViewer", "title": "Storage Object Viewer", "includedPermissions": []string{"storage.objects.get"}})
			case "roles/viewer":
				write(map[string]any{"title": "Viewer", "includedPermissions": []string{"resourcemanager.projects.get"}})
			case "roles/custom.thing":
				write(map[string]any{"title": "Thing", "includedPermissions": []string{"storage.objects.list"}})
			case "roles/iam.serviceAccountUser":
				write(map[string]any{"title": "Service Account User", "includedPermissions": []string{"iam.serviceAccounts.actAs"}})
			default:
				w.WriteHeader(404)
			}
		case strings.HasSuffix(r.URL.Path, "/serviceAccounts"):
			if strings.Contains(r.URL.Path, "beta-proj-22") {
				w.WriteHeader(403) // IAM API not enabled there
				return
			}
			if q.Get("pageToken") == "" && strings.Contains(r.URL.Path, "sec-proj-123") {
				write(map[string]any{"accounts": []any{map[string]any{"email": saEmail}}, "nextPageToken": "n2"})
				return
			}
			if strings.Contains(r.URL.Path, "sec-proj-123") {
				write(map[string]any{"accounts": []any{map[string]any{"email": "Old@sec-proj-123.iam.gserviceaccount.com", "disabled": true}}})
				return
			}
			write(map[string]any{})
		default:
			w.WriteHeader(404)
		}
	})
}

func bind(role string, members ...string) map[string]any {
	return map[string]any{"role": role, "members": members}
}

var policies = map[string]map[string]any{
	"organizations/123": {"bindings": []any{bind("roles/iam.serviceAccountUser", "group:eng@example.com")}},
	"folders/1000":      {"bindings": []any{bind("roles/storage.objectViewer", "domain:example.com", "allAuthenticatedUsers")}},
	"projects/alpha-proj-1": {"bindings": []any{
		bind("roles/owner", "user:Alice@Example.com", "serviceAccount:"+saEmail, "deleted:user:gone@example.com?uid=1"),
		bind("roles/viewer", "projectViewer:alpha-proj-1"),
		map[string]any{"role": "roles/storage.objectViewer", "members": []string{"user:alice@example.com"},
			"condition": map[string]any{"title": "until 2027", "expression": "request.time < timestamp('2027-01-01T00:00:00Z')"}},
		bind("roles/custom.thing", "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*")}},
	"projects/beta-proj-22": {"bindings": []any{bind("roles/storage.objectViewer", "user:bob@example.com")}},
	"projects/sec-proj-123": {},
	// roles.get answers 404 for every role here: privilege must not be guessed quietly
	"projects/gamma-proj-33": {"bindings": []any{
		bind("roles/iam.serviceAccountTokenCreator", "user:eve@example.com"),
		bind("roles/custom.keyman", "user:eve@example.com"),
		map[string]any{"role": "roles/storage.objectViewer", "members": []string{"user:eve@example.com"},
			"condition": map[string]any{"title": "same", "expression": "resource.name.startsWith('a')"}},
		map[string]any{"role": "roles/storage.objectViewer", "members": []string{"user:eve@example.com"},
			"condition": map[string]any{"title": "same", "expression": "resource.name.startsWith('b')"}}}},
}

func (f *fake) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	f.tokens++
	_ = r.ParseForm()
	fail := func() {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`))
	}
	parts := strings.Split(r.Form.Get("assertion"), ".")
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(parts) != 3 {
		fail()
		return
	}
	dec := func(s string, v any) bool {
		b, err := base64.RawURLEncoding.DecodeString(s)
		return err == nil && json.Unmarshal(b, v) == nil
	}
	var hdr map[string]string
	var cl map[string]any
	if !dec(parts[0], &hdr) || !dec(parts[1], &cl) || hdr["alg"] != "RS256" || hdr["kid"] != "kid1" || cl["iss"] != saEmail ||
		cl["scope"] != gcpiam.Scope || !strings.HasSuffix(cl["aud"].(string), "/token") {
		fail()
		return
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(f.pub, crypto.SHA256, d[:], sig) != nil {
		fail()
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gcp-token", "token_type": "Bearer", "expires_in": 3599})
}

type rig struct {
	f   *fake
	srv *connsynctest.Server
	hc  *http.Client
	key string
}

func newRig(t *testing.T, f *fake) *rig {
	t.Helper()
	k, js := newKey(t)
	f.pub = &k.PublicKey
	srv := connsynctest.New(t, f.handler())
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	return &rig{f, srv, hc, js}
}

func (r *rig) cfg(mut ...func(*gcpiam.Config)) gcpiam.Config {
	c := gcpiam.Config{Key: connsync.NewSecret(r.key), OrganizationID: "123", CRMURL: r.srv.URL, IAMURL: r.srv.URL, TokenURL: r.srv.URL + "/token"}
	for _, m := range mut {
		m(&c)
	}
	return c
}

func (r *rig) open(t *testing.T, mut ...func(*gcpiam.Config)) *gcpiam.Connector {
	t.Helper()
	c, err := gcpiam.New(r.cfg(mut...), connsynctest.Runtime, r.hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDiscoverMapsPoliciesRolesAndServiceAccounts(t *testing.T) {
	r := newRig(t, &fake{})
	res, err := r.open(t).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Partial != "" {
		t.Errorf("partial = %q", res.Partial)
	}
	kinds := map[string]string{}
	var parent string
	for _, x := range res.Resources {
		kinds[x.ExternalID] = x.Kind
		if x.ExternalID == "projects/beta-proj-22" {
			parent = strings.Join(x.Tags, ",")
		}
	}
	want := map[string]string{"organizations/123": "gcp_organization", "folders/1000": "gcp_folder", "projects/alpha-proj-1": "gcp_project",
		"projects/beta-proj-22": "gcp_project", "projects/sec-proj-123": "gcp_project"}
	if len(kinds) != len(want) {
		t.Errorf("resources = %v", kinds)
	}
	for id, k := range want {
		if kinds[id] != k {
			t.Errorf("resource %s = %q, want %q", id, kinds[id], k)
		}
	}
	if parent != "gcp,project,parent:folders/1000" {
		t.Errorf("tags = %q", parent)
	}
	perms := map[string]connectors.PermissionRecord{}
	for _, p := range res.Permissions {
		perms[p.ExternalID] = p
	}
	for id, w := range map[string]struct {
		action string
		priv   bool
	}{
		"projects/alpha-proj-1|roles/owner":              {"roles/owner", true},
		"projects/alpha-proj-1|roles/viewer":             {"roles/viewer", false},
		"organizations/123|roles/iam.serviceAccountUser": {"roles/iam.serviceAccountUser", true}, // actAs
		"folders/1000|roles/storage.objectViewer":        {"roles/storage.objectViewer", false},
		"projects/alpha-proj-1|roles/custom.thing":       {"roles/custom.thing", false},
	} {
		p, ok := perms[id]
		if !ok || p.Action != w.action || p.Privileged != w.priv || p.ResourceExternalID != strings.SplitN(id, "|", 2)[0] {
			t.Errorf("permission %s = %+v, want %+v", id, p, w)
		}
	}
	nCond := 0
	for id, p := range perms {
		if strings.HasPrefix(id, "projects/alpha-proj-1|roles/storage.objectViewer|c") && p.Action == "roles/storage.objectViewer (conditional)" {
			nCond++
		}
	}
	if nCond != 1 || len(res.Permissions) != 7 {
		t.Errorf("conditional = %d, %d permissions", nCond, len(res.Permissions))
	}
	accts := map[string]connectors.AccountRecord{}
	for _, a := range res.Accounts {
		accts[a.ExternalID] = a
	}
	if a := accts["user:alice@example.com"]; a.Kind != "user" || a.Identity == nil || a.Identity.Email != "alice@example.com" {
		t.Errorf("alice = %+v", a)
	}
	if a := accts["serviceAccount:"+saEmail]; a.Kind != "service" || a.Status != "active" {
		t.Errorf("service account = %+v", a)
	}
	if a := accts["serviceAccount:old@sec-proj-123.iam.gserviceaccount.com"]; a.Status != "disabled" {
		t.Errorf("listed service account = %+v (pages must be followed)", a)
	}
	if _, ok := accts["user:gone@example.com?uid=1"]; ok || len(accts) != 4 {
		t.Errorf("accounts = %v", accts)
	}
	groups := map[string]connectors.GroupRecord{}
	for _, g := range res.Groups {
		groups[g.ExternalID] = g
	}
	for id, k := range map[string]string{"group:eng@example.com": "google_group", "domain:example.com": "google_domain",
		"allAuthenticatedUsers": "public", "projectViewer:alpha-proj-1": "gcp_convenience"} {
		if groups[id].Kind != k {
			t.Errorf("group %s = %+v", id, groups[id])
		}
	}
	if !groups["allAuthenticatedUsers"].Privileged || groups["projectViewer:alpha-proj-1"].Privileged {
		t.Error("public access must read as privileged, a viewer convenience group must not")
	}
	edge := map[string]bool{}
	for _, e := range res.Edges {
		edge[e.Src.Kind+":"+e.Src.ExternalID+">"+e.Dst.ExternalID+":"+e.Relation] = true
	}
	for _, w := range []string{"account:user:alice@example.com>projects/alpha-proj-1|roles/owner:direct_grant",
		"account:serviceAccount:" + saEmail + ">projects/alpha-proj-1|roles/owner:direct_grant",
		"group:group:eng@example.com>organizations/123|roles/iam.serviceAccountUser:grants"} {
		if !edge[w] {
			t.Errorf("missing edge %s", w)
		}
	}
	for _, b := range r.f.bodies {
		if b != `{"options":{"requestedPolicyVersion":3}}` {
			t.Errorf("getIamPolicy body = %s", b)
		}
	}
}

func TestReadIsReadOnly(t *testing.T) {
	r := newRig(t, &fake{})
	if _, err := r.open(t).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, q := range r.srv.Requests() {
		ok := q.Method == http.MethodGet || (q.Method == http.MethodPost && (q.Path == "/token" || strings.HasSuffix(q.Path, ":getIamPolicy")))
		if !ok {
			t.Errorf("%s %s: not a read", q.Method, q.Path)
		}
	}
	if r.f.tokens != 1 {
		t.Errorf("%d token exchanges, want the token reused", r.f.tokens)
	}
}

func TestExplicitProjectsOnly(t *testing.T) {
	r := newRig(t, &fake{})
	res, err := r.open(t, func(c *gcpiam.Config) { c.OrganizationID, c.ProjectIDs = "", []string{"beta-proj-22"} }).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resources) != 1 || listed(r.srv) {
		t.Errorf("resources = %+v, requests = %v", res.Resources, r.srv.Requests())
	}
	if len(res.Accounts) != 1 || res.Accounts[0].ExternalID != "user:bob@example.com" || res.Partial != "" {
		t.Errorf("accounts = %+v partial = %q (a project whose IAM API is off keeps its policy)", res.Accounts, res.Partial)
	}
}

func TestUnreadablePolicyIsPartial(t *testing.T) {
	r := newRig(t, &fake{deny: map[string]int{"/v3/folders/1000:getIamPolicy": 403}})
	res, err := r.open(t).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Partial, "1 of 5 resources could not be read (folders/1000)") {
		t.Errorf("partial = %q", res.Partial)
	}
	r = newRig(t, &fake{deny: map[string]int{"/v3/": 403}})
	if _, err := r.open(t).Discover(context.Background()); err == nil {
		t.Error("an estate where nothing can be listed read cleanly")
	}
	r = newRig(t, &fake{deny: map[string]int{"/v3/organizations/123:getIamPolicy": 403, "/v3/folders/1000:getIamPolicy": 403, "/v3/projects/": 403}})
	if _, err := r.open(t, func(c *gcpiam.Config) { c.OrganizationID, c.ProjectIDs = "", []string{"alpha-proj-1"} }).Discover(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "no policy could be read") {
		t.Errorf("err = %v", err)
	}
}

// EdgeScopesRead names the resources whose policy was read in full, by the same external ids the permissions carry,
// so the edge pruner can match them; a resource whose policy could not be read is left out, so its edges are kept.
func TestEdgeScopesReadMatchPermissionResourcesAndOmitUnreadScopes(t *testing.T) {
	scopes := func(res *connectors.DiscoveryResult) map[string]bool {
		m := map[string]bool{}
		for _, s := range res.EdgeScopesRead {
			m[s] = true
		}
		return m
	}
	permScopes := func(res *connectors.DiscoveryResult) map[string]bool {
		m := map[string]bool{}
		for _, p := range res.Permissions {
			m[p.ResourceExternalID] = true
		}
		return m
	}
	res, err := newRig(t, &fake{}).open(t).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Partial != "" || len(res.EdgeSnapshotOf) != 1 || res.EdgeSnapshotOf[0] != gcpiam.System {
		t.Fatalf("partial %q, snapshot of %v", res.Partial, res.EdgeSnapshotOf)
	}
	full := scopes(res)
	for _, r := range res.Resources {
		if !full[r.ExternalID] {
			t.Errorf("resource %s was read in full but is not a scope read: %v", r.ExternalID, res.EdgeScopesRead)
		}
	}
	for rid := range permScopes(res) {
		if !full[rid] {
			t.Errorf("permission resource %q is not among the scopes read %v", rid, res.EdgeScopesRead)
		}
	}
	if !slices.IsSorted(res.EdgeScopesRead) {
		t.Errorf("scopes are not sorted: %v", res.EdgeScopesRead)
	}

	// a policy that cannot be read: the scope is omitted, the others stay
	res, err = newRig(t, &fake{deny: map[string]int{"/v3/folders/1000:getIamPolicy": 403}}).open(t).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	part := scopes(res)
	if res.Partial == "" || part["folders/1000"] || permScopes(res)["folders/1000"] {
		t.Errorf("partial %q: unread folder in scopes %v, permissions %v", res.Partial, res.EdgeScopesRead, permScopes(res))
	}
	if len(part) != len(full)-1 {
		t.Errorf("scopes read = %v, want all but folders/1000 of %v", res.EdgeScopesRead, full)
	}
	for rid := range permScopes(res) {
		if !part[rid] {
			t.Errorf("permission resource %q is not among the scopes read %v", rid, res.EdgeScopesRead)
		}
	}
}

func TestBadKeyIsRefusedWithoutEchoingIt(t *testing.T) {
	r := newRig(t, &fake{})
	// a key the server does not know: the token endpoint answers 400 invalid_grant
	_, js := newKey(t)
	c := r.open(t, func(c *gcpiam.Config) { c.Key = connsync.NewSecret(js) })
	_, err := c.Discover(context.Background())
	if !errors.Is(err, gcpiam.ErrCredential) || strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "kid1") {
		t.Errorf("err = %v", err)
	}
	if _, perr := c.Probe(context.Background()); !errors.Is(perr, gcpiam.ErrCredential) {
		t.Errorf("probe err = %v", perr)
	}
}

func TestNewGuards(t *testing.T) {
	_, js := newKey(t)
	hc, _ := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	prod := connsync.Runtime{Env: config.Prod}
	good := gcpiam.Config{Key: connsync.NewSecret(js), OrganizationID: "123"}
	if _, err := gcpiam.New(good, prod, hc, nil); err != nil {
		t.Fatalf("Google endpoints in prod: %v", err)
	}
	notSA, _ := json.Marshal(map[string]string{"type": "authorized_user", "client_email": saEmail})
	for name, tc := range map[string]struct {
		mut func(*gcpiam.Config)
		rt  connsync.Runtime
	}{
		"CRM override in prod":     {func(c *gcpiam.Config) { c.CRMURL = "https://crm.example.com" }, prod},
		"token override in prod":   {func(c *gcpiam.Config) { c.TokenURL = "https://idp.example.com/token" }, prod},
		"loopback in prod":         {func(c *gcpiam.Config) { c.IAMURL = "http://127.0.0.1:1" }, prod},
		"override in test":         {func(c *gcpiam.Config) { c.IAMURL = "https://iam.example.com" }, connsync.Runtime{Env: "test"}},
		"no scope":                 {func(c *gcpiam.Config) { c.OrganizationID = "" }, prod},
		"organization not a num":   {func(c *gcpiam.Config) { c.OrganizationID = "organizations/1" }, prod},
		"folder not a number":      {func(c *gcpiam.Config) { c.FolderIDs = []string{"../1"} }, prod},
		"project with a slash":     {func(c *gcpiam.Config) { c.ProjectIDs = []string{"a/b"} }, prod},
		"key is not JSON":          {func(c *gcpiam.Config) { c.Key = connsync.NewSecret("hunter2") }, prod},
		"key is a user credential": {func(c *gcpiam.Config) { c.Key = connsync.NewSecret(string(notSA)) }, prod},
		"key has no private key": {func(c *gcpiam.Config) {
			c.Key = connsync.NewSecret(`{"type":"service_account","client_email":"` + saEmail + `"}`)
		}, prod},
	} {
		c := good
		tc.mut(&c)
		if _, err := gcpiam.New(c, tc.rt, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := good
	c.CRMURL = "http://127.0.0.1:9"
	if _, err := gcpiam.New(c, connsync.Runtime{Env: config.Dev, AllowLoopback: true}, hc, nil); err != nil {
		t.Errorf("dev override: %v", err)
	}
	c.CRMURL, c.TokenURL = gcpiam.DefaultCRMURL+"/", gcpiam.DefaultTokenURL
	if _, err := gcpiam.New(c, prod, hc, nil); err != nil {
		t.Errorf("the defaults spelled out are not overrides: %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	r := newRig(t, &fake{})
	env := map[string]string{"TESSERA_GCP_KEY": "env:GK", "GK": r.key, "TESSERA_GCP_PROJECT_IDS": "alpha-proj-1, beta-proj-22",
		"TESSERA_GCP_CRM_URL": r.srv.URL, "TESSERA_GCP_IAM_URL": r.srv.URL, "TESSERA_GCP_TOKEN_URL": r.srv.URL + "/token"}
	c, err := gcpiam.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, r.hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Discover(context.Background())
	if err != nil || len(res.Resources) != 2 || c.System() != "gcp" {
		t.Errorf("res = %+v, err = %v", res, err)
	}
	if _, err := gcpiam.FromEnv(func(string) string { return "" }, connsynctest.Runtime, r.hc, nil); err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Errorf("err = %v", err)
	}
}

func TestProbe(t *testing.T) {
	r := newRig(t, &fake{})
	c := r.open(t)
	p, err := c.Probe(context.Background())
	if err != nil || p.Identity != saEmail || p.Resources != 5 || p.Bindings == 0 {
		t.Errorf("probe = %+v, err = %v", p, err)
	}
}

// listed reports whether the connector listed folders or projects (it must not when only projects are configured).
func listed(s *connsynctest.Server) bool {
	for _, q := range s.Requests() {
		if q.Path == "/v3/folders" || q.Path == "/v3/projects" {
			return true
		}
	}
	return false
}

// The result ingests into the graph: every edge names a record of the same result, and a second sync
// with the same data changes nothing.
func TestIngestsIntoTheGraph(t *testing.T) {
	r := newRig(t, &fake{})
	db := testkit.Open(t)
	tn := tenancy.MustParse("00000000-0000-4000-8000-0000000000e2")
	testkit.CreateTenant(t, db, tn, "gcp-iam")
	for i := 0; i < 2; i++ {
		var st ingest.SyncStats
		err := db.InTenant(context.Background(), tn, func(c *store.TenantTx) error {
			var err error
			st, err = ingest.Sync(c, testkit.Now, []connectors.Connector{r.open(t)}, nil)
			return err
		})
		if err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
		if d := st.Discovery; d.Accounts != 4 || d.Permissions != 7 || d.Resources != 5 || d.Edges == 0 {
			t.Errorf("sync %d: %+v", i, d)
		}
	}
}

// A role that cannot be read is said so (Partial), the well-known privileged roles stay privileged without
// roles.get, and conditions that differ only in their expression are different permissions.
func TestUnreadableRolesArePartialAndKnownPrivilegedRolesStayPrivileged(t *testing.T) {
	r := newRig(t, &fake{})
	res, err := r.open(t, func(c *gcpiam.Config) { c.OrganizationID, c.ProjectIDs = "", []string{"gamma-proj-33"} }).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Partial, "bound roles could not be read") {
		t.Errorf("partial = %q", res.Partial)
	}
	priv := map[string]bool{}
	cond := 0
	for _, p := range res.Permissions {
		priv[p.ExternalID] = p.Privileged
		if strings.HasPrefix(p.ExternalID, "projects/gamma-proj-33|roles/storage.objectViewer|c") {
			cond++
		}
	}
	if !priv["projects/gamma-proj-33|roles/iam.serviceAccountTokenCreator"] {
		t.Error("serviceAccountTokenCreator must be privileged even when roles.get fails")
	}
	if priv["projects/gamma-proj-33|roles/custom.keyman"] {
		t.Error("an unreadable custom role is judged by name only")
	}
	if cond != 2 {
		t.Errorf("%d conditional permissions, want 2 (one per expression)", cond)
	}
}

func TestKnownPrivilegedRoles(t *testing.T) {
	for _, name := range []string{"roles/owner", "roles/editor", "roles/iam.securityAdmin", "roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser",
		"roles/iam.serviceAccountKeyAdmin", "roles/resourcemanager.organizationAdmin", "roles/iam.workloadIdentityUser"} {
		if !gcpiam.PrivilegedRole(name, nil, false) {
			t.Errorf("%s is not privileged", name)
		}
	}
	if gcpiam.PrivilegedRole("roles/viewer", nil, false) || gcpiam.PrivilegedRole("roles/storage.objectViewer", []string{"storage.objects.get"}, true) {
		t.Error("a viewer role is privileged")
	}
}
