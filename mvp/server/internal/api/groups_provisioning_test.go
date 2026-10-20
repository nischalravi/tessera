package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/provisioning"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Group provisioning (issue #54, GR-11). The engine of provisioning is covered
// in internal/groups/provisioning; these tests cover the routes: validation,
// secrets, the adopt-first rule, diagnostics, tenant isolation and permissions.

// memTarget is a minimal in-memory provisioning target.
type memTarget struct {
	mu     sync.Mutex
	groups map[string]*provisioning.TargetGroup
}

func (m *memTarget) Capabilities() provisioning.Capabilities {
	return provisioning.Capabilities{Groups: true, Memberships: true, Readable: true, MaxBatch: 10}
}
func (m *memTarget) Close() error { return nil }
func (m *memTarget) ReadAll(context.Context, provisioning.Scope) (provisioning.TargetState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := provisioning.NewState()
	for k, g := range m.groups {
		c := *g
		st.Groups[k] = &c
	}
	return st, nil
}
func (m *memTarget) Read(_ context.Context, refs []provisioning.TargetRef) (provisioning.TargetState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := provisioning.NewState()
	for _, r := range refs {
		if g := m.groups[provisioning.Key(r.Name)]; g != nil {
			c := *g
			st.Groups[provisioning.Key(r.Name)] = &c
		}
	}
	return st, nil
}
func (m *memTarget) Apply(_ context.Context, ops []provisioning.Op) ([]provisioning.OpResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]provisioning.OpResult, len(ops))
	for i, op := range ops {
		out[i] = provisioning.OpResult{ID: op.ID, Ref: op.Ref}
		k := provisioning.Key(op.Ref.Name)
		g := m.groups[k]
		if op.Kind == provisioning.OpCreate {
			g = &provisioning.TargetGroup{Ref: op.Ref}
			m.groups[k] = g
		}
		if g == nil {
			continue
		}
		for _, r := range op.Remove {
			g.Members = slices.DeleteFunc(g.Members, func(x string) bool { return x == r })
		}
		g.Members = append(g.Members, op.Add...)
		if op.Kind == provisioning.OpDelete {
			delete(m.groups, k)
		}
	}
	return out, nil
}

type provAPI struct {
	grpClient
	f      *storetest.Fixture
	svc    *provisioning.Service
	target *memTarget
	clk    *ticking
}

// ticking is a clock the test moves by a minute before each runner pass, so
// runs started one after the other have different start times.
type ticking struct {
	mu sync.Mutex
	t  time.Time
}

func (c *ticking) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *ticking) advance() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Minute)
}

func newProvAPI(t *testing.T, f *storetest.Fixture, tenant tenancy.ID) provAPI {
	t.Helper()
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	target := &memTarget{groups: map[string]*provisioning.TargetGroup{}}
	clk := &ticking{t: storetest.Now}
	clock := clk.now
	svc := &provisioning.Service{DB: f.DB, Sealer: sealer, Clock: clock, Sleep: func(context.Context, time.Duration) {},
		Open: func(context.Context, provisioning.TargetSpec) (provisioning.Provisioner, error) { return target, nil },
		Deps: provisioning.Deps{AllowPlainLDAP: false}}
	srv := New(Config{Store: f.DB, Clock: clock, Policies: policy.NewLoader(policies.FS), Sealer: sealer, Provisioning: svc,
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{"http://localhost:5173"}, Env: "test",
		RateLimits: noRateLimits})
	return provAPI{grpClient{client{t, asAdmin(t, srv, f.DB, tenant, storetest.Now).Handler()}}, f, svc, target, clk}
}

const provBody = `{"name":"Directory","target_type":"scim2","secret":{"token":"super-secret-token-value"},
 "config":{"account_system":"okta","group_name":"{{.Name | replace \":\" \"-\"}}","member_ref":"{{.ExternalID}}",
 "target":{"base_url":"https://scim.example.com/scim/v2"}}}`

func (p provAPI) create() map[string]any {
	return p.call("POST", "/api/groups/provisioners", provBody, 201)
}

func (p provAPI) once(tenant tenancy.ID) {
	p.t.Helper()
	p.clk.advance()
	r := &provisioning.Runner{Svc: p.svc, Clock: p.clk.now}
	if err := r.Once(context.Background()); err != nil {
		p.t.Fatal(err)
	}
}

func TestGroupsProvisioningAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	p := newProvAPI(t, f, f.B.ID)
	app := p.folder("", "app")
	team := p.group(app, "team")
	alice := f.B.IDs["alice"]
	p.member(team, alice)

	if got := p.call("GET", "/api/groups/provisioners", "", 200); len(got["items"].([]any)) != 0 {
		t.Fatalf("provisioners before any: %v", got)
	}
	created := p.create()
	id := created["id"].(string)
	if created["mode"] != "adopt" || created["target_type"] != "scim2" || created["version"] != float64(1) || created["needs_full_sync"] != true {
		t.Fatalf("created = %v", created)
	}
	if keys := created["secret_keys_set"].([]any); len(keys) != 1 || keys[0] != "token" {
		t.Errorf("secret_keys_set = %v", keys)
	}
	// no response, listing or audit event ever carries the credential
	bodies := []string{p.do("GET", "/api/groups/provisioners", "").Body.String(), p.do("GET", "/api/groups/provisioners/"+id, "").Body.String(),
		p.do("GET", "/api/audit?limit=500", "").Body.String(), fmt.Sprint(created)}
	for _, b := range bodies {
		if strings.Contains(b, "super-secret-token-value") {
			t.Errorf("the credential appears in a response: %.200s", b)
		}
	}
	// stored sealed, bound to the tenant, the table, the column and the provisioner
	var enc []byte
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		pr, err := tx.Provisioner(id)
		enc = pr.SecretEnc
		return err
	}); err != nil || len(enc) == 0 || strings.Contains(string(enc), "super-secret") {
		t.Fatalf("stored secret = %q, %v", enc, err)
	}

	// duplicates and bad input
	p.call("POST", "/api/groups/provisioners", provBody, 409)
	for name, body := range map[string]string{
		"no name":            `{"target_type":"scim2","config":{}}`,
		"unknown type":       strings.Replace(provBody, `"scim2"`, `"carrier-pigeon"`, 1),
		"no token":           strings.Replace(provBody, `"secret":{"token":"super-secret-token-value"},`, "", 1),
		"foreign secret":     strings.Replace(provBody, `"token":"super-secret-token-value"`, `"password":"x"`, 1),
		"no account sys":     strings.Replace(provBody, `"account_system":"okta",`, "", 1),
		"bad template":       strings.Replace(provBody, `{{.Name | replace`, `{{.Name | exec`, 1),
		"http base url":      strings.Replace(provBody, `https://scim.example.com`, `ftp://scim.example.com`, 1),
		"bad schedule":       strings.Replace(provBody, `"name":"Directory",`, `"name":"Other","full_schedule":"every day",`, 1),
		"bad failsafe":       strings.Replace(provBody, `"name":"Directory",`, `"name":"Other","failsafe":{"max_deletes":-1},`, 1),
		"unknown field":      strings.Replace(provBody, `"name":"Directory",`, `"name":"Other","mode":"active",`, 1),
		"unknown conn":       strings.Replace(provBody, `"name":"Directory",`, `"name":"Other","connection_id":"00000000-0000-4000-8000-00000000dead",`, 1),
		"sql not enabled":    `{"name":"S","target_type":"sql","config":{"account_system":"x","target":{"file":"m.db"}}}`,
		"plain ldap in prod": `{"name":"L","target_type":"ldap","secret":{"bind_password":"x"},"config":{"account_system":"x","target":{"url":"ldap://h","security":"none","base_dn":"dc=x","bind_dn":"cn=a"}}}`,
	} {
		if rec := p.do("POST", "/api/groups/provisioners", body); rec.Code != 422 && rec.Code != 409 {
			t.Errorf("%s: status %d: %.200s", name, rec.Code, rec.Body.String())
		}
	}

	// reads
	if got := p.call("GET", "/api/groups/provisioners", "", 200); len(got["items"].([]any)) != 1 {
		t.Errorf("list = %v", got)
	}
	got := p.call("GET", "/api/groups/provisioners/"+id, "", 200)
	if got["provisioner"].(map[string]any)["name"] != "Directory" || got["marks"] != float64(0) || got["event_lag"] == nil {
		t.Errorf("get = %v", got)
	}
	p.call("GET", "/api/groups/provisioners/not-a-uuid", "", 404)
	p.call("GET", "/api/groups/provisioners/00000000-0000-4000-8000-00000000dead", "", 404)

	// marks
	p.call("PUT", "/api/groups/provisioners/"+id+"/marks", `{"object_type":"folder","object_id":"`+app+`","scope":"sub"}`, 200)
	m := p.call("PUT", "/api/groups/provisioners/"+id+"/marks", `{"object_type":"group","object_id":"`+team+`","include":false}`, 200)
	if m["name"] != "app:team" || m["include"] != false || m["scope"] != "self" {
		t.Errorf("mark = %v", m)
	}
	for name, body := range map[string]string{
		"folder without scope": `{"object_type":"folder","object_id":"` + app + `"}`,
		"group with scope":     `{"object_type":"group","object_id":"` + team + `","scope":"sub"}`,
		"unknown folder":       `{"object_type":"folder","object_id":"00000000-0000-4000-8000-00000000dead","scope":"one"}`,
		"bad id":               `{"object_type":"folder","object_id":"x","scope":"one"}`,
		"bad type":             `{"object_type":"user","object_id":"` + team + `"}`,
		"bad metadata":         `{"object_type":"group","object_id":"` + team + `","metadata":{"a":[1]}}`,
	} {
		if rec := p.do("PUT", "/api/groups/provisioners/"+id+"/marks", body); rec.Code != 422 {
			t.Errorf("mark %s: status %d: %.200s", name, rec.Code, rec.Body.String())
		}
	}
	if items := p.call("GET", "/api/groups/provisioners/"+id+"/marks", "", 200)["items"].([]any); len(items) != 2 {
		t.Errorf("marks = %v", items)
	}
	p.call("DELETE", "/api/groups/provisioners/"+id+"/marks/group/"+team, "", 200)
	p.call("DELETE", "/api/groups/provisioners/"+id+"/marks/group/"+team, "", 404)
	p.call("DELETE", "/api/groups/provisioners/"+id+"/marks/user/"+team, "", 404)

	// diagnostics: explains and shows the ops, applies nothing
	d := p.call("POST", "/api/groups/provisioners/"+id+"/diagnose?group="+team+"&identity="+fmt.Sprint(alice), "", 200)
	if d["provisioned"] != true || d["target_name"] != "app-team" || !strings.Contains(d["why"].(string), "folder mark on app (sub)") {
		t.Fatalf("diagnose = %v", d)
	}
	if ops := d["ops"].([]any); len(ops) != 1 || ops[0].(map[string]any)["op"] != "create" {
		t.Errorf("ops = %v", d["ops"])
	}
	if id := d["identity"].(map[string]any); id["member"] != true || id["account"] != true || id["reference"] != "alice" {
		t.Errorf("identity = %v", id)
	}
	if len(p.target.groups) != 0 {
		t.Error("diagnose wrote to the target")
	}
	for _, q := range []string{"", "?group=x", "?group=" + team + "&identity=abc", "?group=" + team + "&identity=0"} {
		if rec := p.do("POST", "/api/groups/provisioners/"+id+"/diagnose"+q, ""); rec.Code != 422 {
			t.Errorf("diagnose%s = %d", q, rec.Code)
		}
	}
	p.call("POST", "/api/groups/provisioners/"+id+"/diagnose?group=00000000-0000-4000-8000-00000000dead", "", 404)

	// enabling needs a reviewed first run; the first run changes nothing
	cur := p.call("GET", "/api/groups/provisioners/"+id, "", 200)["provisioner"].(map[string]any)
	patch := func(body string, want int) map[string]any {
		return p.call("PATCH", "/api/groups/provisioners/"+id, body, want)
	}
	patch(fmt.Sprintf(`{"version":%v,"mode":"active"}`, cur["version"]), 409)
	patch(`{"mode":"active"}`, 422)
	patch(fmt.Sprintf(`{"version":%v,"mode":"turbo"}`, cur["version"]), 422)
	patch(`{"version":99,"name":"x"}`, 409)
	if got := p.call("POST", "/api/groups/provisioners/"+id+"/sync", `{"approve_failsafe":true}`, 422); got["error"] == nil {
		t.Errorf("approving in adopt mode = %v", got)
	}
	if got := p.call("POST", "/api/groups/provisioners/"+id+"/sync", "", 202); got["queued"] != true {
		t.Errorf("sync = %v", got)
	}
	p.once(f.B.ID)
	runs := p.call("GET", "/api/groups/provisioners/"+id+"/runs", "", 200)["items"].([]any)
	if len(runs) != 1 || runs[0].(map[string]any)["mode"] != "adopt" || runs[0].(map[string]any)["status"] != "done" {
		t.Fatalf("runs = %v", runs)
	}
	if len(p.target.groups) != 0 {
		t.Fatal("an adopt-mode run wrote to the target")
	}
	runID := runs[0].(map[string]any)["id"].(string)
	ops := p.call("GET", "/api/groups/provisioners/"+id+"/ops?run="+runID+"&status=skipped", "", 200)["items"].([]any)
	if len(ops) != 1 || ops[0].(map[string]any)["status"] != "skipped" || ops[0].(map[string]any)["op"] != "create" {
		t.Errorf("ops = %v", ops)
	}
	for _, q := range []string{"?status=bogus", "?run=x", "?limit=0"} {
		if rec := p.do("GET", "/api/groups/provisioners/"+id+"/ops"+q, ""); rec.Code != 422 {
			t.Errorf("ops%s = %d", q, rec.Code)
		}
	}

	cur = p.call("GET", "/api/groups/provisioners/"+id, "", 200)["provisioner"].(map[string]any)
	act := patch(fmt.Sprintf(`{"version":%v,"mode":"active","full_schedule":"30 3 * * *","failsafe":{"max_deletes":5}}`, cur["version"]), 200)
	if act["mode"] != "active" || act["full_schedule"] != "30 3 * * *" || act["version"] != cur["version"].(float64)+1 || act["needs_full_sync"] != true {
		t.Errorf("updated = %v", act)
	}
	// replacing the credential keeps working and never shows it
	act = patch(fmt.Sprintf(`{"version":%v,"secret":{"token":"another-token-value"}}`, act["version"]), 200)
	if strings.Contains(fmt.Sprint(act), "another-token-value") {
		t.Errorf("the new credential is in the response: %v", act)
	}
	p.once(f.B.ID) // the folder mark (sub) covers the group
	if g := p.target.groups["app-team"]; g == nil || !slices.Equal(g.Members, []string{"alice"}) {
		t.Errorf("the group was not provisioned: %+v", g)
	}
	owned := p.call("GET", "/api/groups/provisioners/"+id+"/groups", "", 200)["items"].([]any)
	if len(owned) != 1 || owned[0].(map[string]any)["status"] != "synced" {
		t.Errorf("owned = %v", owned)
	}
	// opting the group out would delete it on the target: held until an admin approves
	p.call("PUT", "/api/groups/provisioners/"+id+"/marks", `{"object_type":"group","object_id":"`+team+`","include":false}`, 200)
	p.once(f.B.ID)
	if p.target.groups["app-team"] == nil {
		t.Error("the group was deleted without approval")
	}
	lastRun := func() map[string]any {
		return p.call("GET", "/api/groups/provisioners/"+id+"/runs?limit=1", "", 200)["items"].([]any)[0].(map[string]any)
	}
	if r := lastRun(); r["status"] != "held" || !strings.Contains(fmt.Sprint(r["summary"]), "group deletions exceed the limit of 0") {
		t.Errorf("run = %v", r)
	}
	p.call("POST", "/api/groups/provisioners/"+id+"/sync", `{"approve_failsafe":true}`, 202)
	p.once(f.B.ID)
	if p.target.groups["app-team"] != nil || lastRun()["status"] != "done" {
		t.Errorf("approved run: %v, target %v", lastRun(), p.target.groups)
	}

	// pausing refuses a sync request
	cur = p.call("GET", "/api/groups/provisioners/"+id, "", 200)["provisioner"].(map[string]any)
	patch(fmt.Sprintf(`{"version":%v,"mode":"paused"}`, cur["version"]), 200)
	p.call("POST", "/api/groups/provisioners/"+id+"/sync", "", 409)

	// delete
	p.call("DELETE", "/api/groups/provisioners/"+id, "", 200)
	p.call("GET", "/api/groups/provisioners/"+id, "", 404)
	p.call("DELETE", "/api/groups/provisioners/"+id, "", 404)
	audit := p.do("GET", "/api/audit?limit=500", "").Body.String()
	for _, action := range []string{"groups.provisioner.created", "groups.provisioner.updated", "groups.provisioner.mark_set",
		"groups.provisioner.sync_requested", "groups.prov.run", "groups.prov.held", "groups.provisioner.deleted"} {
		if !strings.Contains(audit, action) {
			t.Errorf("the audit ledger has no %s event", action)
		}
	}
}

// Another tenant's provisioners look nonexistent, and its marks cannot name them.
func TestGroupsProvisioningTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := newProvAPI(t, f, f.A.ID)
	b := newProvAPI(t, f, f.B.ID)
	ag := a.group(a.folder("", "app"), "admins")
	aid := a.create()["id"].(string)
	a.call("PUT", "/api/groups/provisioners/"+aid+"/marks", `{"object_type":"group","object_id":"`+ag+`"}`, 200)
	bg := b.group(b.folder("", "app"), "mine")
	if got := b.call("GET", "/api/groups/provisioners", "", 200); len(got["items"].([]any)) != 0 {
		t.Errorf("B sees A's provisioners: %v", got)
	}
	base := "/api/groups/provisioners/" + aid
	b.call("GET", base, "", 404)
	b.call("PATCH", base, `{"version":1,"name":"x"}`, 404)
	b.call("DELETE", base, "", 404)
	b.call("GET", base+"/marks", "", 404)
	b.call("PUT", base+"/marks", `{"object_type":"group","object_id":"`+bg+`"}`, 404)
	b.call("DELETE", base+"/marks/group/"+ag, "", 404)
	b.call("POST", base+"/sync", "", 404)
	b.call("GET", base+"/runs", "", 404)
	b.call("GET", base+"/ops", "", 404)
	b.call("GET", base+"/groups", "", 404)
	b.call("POST", base+"/diagnose?group="+bg, "", 404)
	// B's provisioner cannot mark A's group or folder
	bid := b.call("POST", "/api/groups/provisioners", strings.Replace(provBody, "Directory", "Mine", 1), 201)["id"].(string)
	b.call("PUT", "/api/groups/provisioners/"+bid+"/marks", `{"object_type":"group","object_id":"`+ag+`"}`, 422)
	b.call("POST", "/api/groups/provisioners/"+bid+"/diagnose?group="+ag, "", 404)
	// the same name is free in another tenant
	if got := a.call("GET", "/api/groups/provisioners/"+aid, "", 200); got["marks"] != float64(1) {
		t.Errorf("A's provisioner after B's attempts = %v", got)
	}
}

func TestGroupsProvisioningRoutesRequireTenantAdmin(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	id := "00000000-0000-4000-8000-000000000000"
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		for _, tc := range [][3]string{
			{"GET", "/api/groups/provisioners", ""}, {"POST", "/api/groups/provisioners", provBody},
			{"GET", "/api/groups/provisioners/" + id, ""}, {"PATCH", "/api/groups/provisioners/" + id, `{"version":1}`},
			{"DELETE", "/api/groups/provisioners/" + id, ""}, {"GET", "/api/groups/provisioners/" + id + "/marks", ""},
			{"PUT", "/api/groups/provisioners/" + id + "/marks", `{"object_type":"group","object_id":"` + id + `"}`},
			{"DELETE", "/api/groups/provisioners/" + id + "/marks/group/" + id, ""},
			{"POST", "/api/groups/provisioners/" + id + "/sync", ""}, {"GET", "/api/groups/provisioners/" + id + "/runs", ""},
			{"GET", "/api/groups/provisioners/" + id + "/ops", ""}, {"GET", "/api/groups/provisioners/" + id + "/groups", ""},
			{"POST", "/api/groups/provisioners/" + id + "/diagnose?group=" + id, ""},
		} {
			if rec := serve(h, authed(l, tc[0], tc[1], tc[2])); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s = %d, want 403", role, tc[0], tc[1], rec.Code)
			}
		}
	}
}
