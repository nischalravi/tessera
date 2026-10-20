package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/cliauth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/plan"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The groups commands and declarative plans against an in-process Tessera API
// (issue #49, GR-6): the real router and authorization server, so every step
// is authorized and audited as it is for the UI.

var tenantAdmin = []auth.Role{auth.RoleTenantAdmin}

// domainEvents counts the audit events that are not request records: what the
// changes themselves wrote.
func (w *world) domainEvents() int {
	w.t.Helper()
	n := 0
	if err := w.db.ReadTenant(context.Background(), w.tenant, func(tx *store.TenantTx) error {
		all, err := tx.AuditEventsRange(1, 0, 0)
		for _, e := range all {
			if !strings.HasPrefix(e.Action, "http.") {
				n++
			}
		}
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	return n
}

func (w *world) planFile(content string) string {
	w.t.Helper()
	p := filepath.Join(w.t.TempDir(), "plan.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *world) ok(args ...string) result {
	w.t.Helper()
	r := w.run(args...)
	if r.code != 0 {
		w.t.Fatalf("%v exited %d\nstdout: %s\nstderr: %s", args, r.code, r.stdout, r.stderr)
	}
	return r
}

// client is the signed-in session, as the groups commands use it.
func (w *world) client() plan.Client {
	dir, err := cliauth.DefaultDir(func(k string) string { return map[string]string{"TESSERA_CONFIG_DIR": w.dir}[k] })
	if err != nil {
		w.t.Fatal(err)
	}
	hc, err := newHTTPClient("dev")
	if err != nil {
		w.t.Fatal(err)
	}
	return apiClient{&cliauth.Client{HTTP: hc, Store: &cliauth.Store{Dir: dir}, Now: w.clock.Now}}
}

func (w *world) applicationPlan() string {
	return fmt.Sprintf(`
folders:
  - name: app
  - name: app:foo
    template: application
groups:
  - name: app:foo:service:ref:testers
    members:
      add: [identity:%d, identity:%d, "group:app:foo:service:policy:foo_user_allow_manual"]
  - name: app:foo:service:policy:foo_user_allow_manual
    members:
      add: [%d]
privileges:
  - object: folder:app:foo
    grant: {create: ["identity:%d"], scope: sub}
`, w.ids["alice"], w.ids["bob"], w.ids["carol"], w.ids["alice"])
}

func TestPlan_ApplyIsIdempotent(t *testing.T) {
	w := newWorld(t)
	if r := w.login("alice@tiny.example", tenantAdmin, "approve"); r.code != 0 {
		t.Fatalf("login: %s %s", r.stdout, r.stderr)
	}
	file := w.planFile(w.applicationPlan())

	// plan shows the diff and changes nothing
	before := w.domainEvents()
	r := w.ok("groups", "plan", "-f", file)
	for _, want := range []string{"+ folder  app:foo:security", "+ group   app:foo:security:fooAdmin",
		"composite complement of app:foo:service:policy:foo_user_allow, app:foo:service:policy:foo_user_deny",
		"+ grant   folder:app:foo  stem_admin to group:app:foo:security:fooAdmin (inherited by folders, scope sub)",
		"+ member  app:foo:service:ref:testers <- identity:", "Impact:"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("plan output lacks %q:\n%s", want, r.stdout)
		}
	}
	if got := w.domainEvents(); got != before {
		t.Fatalf("plan wrote %d audit events", got-before)
	}
	if ls := w.ok("groups", "ls"); strings.TrimSpace(ls.stdout) != "" {
		t.Fatalf("plan created things: %s", ls.stdout)
	}

	// apply creates everything
	r = w.ok("groups", "apply", "-f", file)
	if !strings.Contains(r.stdout, "Applied: 6 folders, 6 groups") {
		t.Errorf("apply output:\n%s", r.stdout)
	}
	ls := w.ok("groups", "ls", "app:foo").stdout
	for _, want := range []string{"app:foo:service:policy:foo_user  (group, composite)", "app:foo:security:fooAdmin"} {
		if !strings.Contains(ls, want) {
			t.Errorf("ls lacks %q:\n%s", want, ls)
		}
	}
	members := w.ok("groups", "members", "ls", "app:foo:service:ref:testers").stdout
	if strings.Count(members, "identity:") != 2 || !strings.Contains(members, "group:") {
		t.Errorf("members:\n%s", members)
	}
	// the template's composite is real: allow minus deny
	if eff := w.ok("groups", "members", "ls", "app:foo:service:policy:foo_user_allow_manual", "--filter", "effective").stdout; !strings.Contains(eff, "identity:") {
		t.Errorf("effective members of the manual group:\n%s", eff)
	}

	// the second run finds nothing to do, in plan and in apply, and writes nothing
	after := w.domainEvents()
	for _, cmd := range []string{"plan", "apply"} {
		r = w.ok("groups", cmd, "-f", file)
		if !strings.Contains(r.stdout, "No changes") {
			t.Errorf("second %s:\n%s", cmd, r.stdout)
		}
	}
	if got := w.domainEvents(); got != after {
		t.Errorf("the second runs wrote %d audit events", got-after)
	}

	// a member change is a mini plan too, and removing what is gone is a no-op
	w.ok("groups", "members", "rm", "app:foo:service:ref:testers", fmt.Sprint(w.ids["bob"]))
	if r = w.ok("groups", "members", "rm", "app:foo:service:ref:testers", fmt.Sprint(w.ids["bob"])); !strings.Contains(r.stdout, "Nothing to do") {
		t.Errorf("second rm:\n%s", r.stdout)
	}
	w.ok("groups", "members", "add", "app:foo:service:ref:testers", fmt.Sprint(w.ids["bob"]), "--reason", "back again")
}

// TestPlan_BatchesReplayWithTheSameKey sends the same plan twice from a stale
// view of the server: the second batch carries the first one's
// Idempotency-Key, so the server replays its answer and writes nothing.
func TestPlan_BatchesReplayWithTheSameKey(t *testing.T) {
	w := newWorld(t)
	if r := w.login("alice@tiny.example", tenantAdmin, "approve"); r.code != 0 {
		t.Fatalf("login: %s %s", r.stdout, r.stderr)
	}
	w.ok("groups", "apply", "-f", w.planFile("folders:\n  - name: app\ngroups:\n  - name: app:team\n"))
	spec, err := plan.Parse(strings.NewReader(fmt.Sprintf("groups:\n  - name: app:team\n    members:\n      add: [%d, %d]\n", w.ids["alice"], w.ids["bob"])))
	if err != nil {
		t.Fatal(err)
	}
	c, ctx := w.client(), context.Background()
	live, err := plan.Load(ctx, c, spec)
	if err != nil {
		t.Fatal(err)
	}
	p, err := plan.Compute(spec, live)
	if err != nil || len(p.Actions) != 2 {
		t.Fatalf("plan: %v %+v", err, p)
	}
	if _, err := plan.Apply(ctx, c, p, live, plan.Options{}); err != nil {
		t.Fatal(err)
	}
	batches := len(w.events("groups.member.batch"))
	if batches != 1 {
		t.Fatalf("%d batches audited", batches)
	}
	if _, err := plan.Apply(ctx, c, p, live, plan.Options{}); err != nil { // same plan, same live view: same key
		t.Fatal(err)
	}
	if got := len(w.events("groups.member.batch")); got != batches {
		t.Errorf("the repeated batch wrote %d more events", got-batches)
	}
	// another run id is a different request
	if _, err := plan.Apply(ctx, c, p, live, plan.Options{RunID: "second"}); err != nil {
		t.Fatal(err)
	}
	if got := len(w.events("groups.member.batch")); got != batches+1 {
		t.Errorf("a new run id wrote %d batch events, want 1", got-batches)
	}
}

func TestExportThenApply_RoundTrip(t *testing.T) {
	w := newWorld(t)
	if r := w.login("alice@tiny.example", tenantAdmin, "approve"); r.code != 0 {
		t.Fatalf("login: %s %s", r.stdout, r.stderr)
	}
	w.ok("groups", "apply", "-f", w.planFile(w.applicationPlan()))

	out := filepath.Join(t.TempDir(), "foo.yaml")
	w.ok("groups", "export", "app:foo", "-o", out)
	exported, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// the export of a folder describes the server as it is: nothing to change
	if r := w.ok("groups", "plan", "-f", out); !strings.Contains(r.stdout, "No changes") {
		t.Fatalf("plan of the export:\n%s\n--- export:\n%s", r.stdout, exported)
	}
	// apply it under another name, export that, and the two exports agree
	renamed := w.planFile(strings.ReplaceAll(string(exported), "foo", "bar"))
	w.ok("groups", "apply", "-f", renamed)
	out2 := filepath.Join(t.TempDir(), "bar.yaml")
	w.ok("groups", "export", "app:bar", "-o", out2)
	again, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(string(again), "bar", "foo"); got != string(exported) {
		t.Errorf("the copy exports differently:\n--- original\n%s\n--- copy\n%s", exported, got)
	}
}

func TestGroupsCLI_RefusedWithoutThePrivilege(t *testing.T) {
	w := newWorld(t)
	if r := w.login("alice@tiny.example", tenantAdmin, "approve"); r.code != 0 {
		t.Fatalf("login: %s %s", r.stdout, r.stderr)
	}
	w.ok("groups", "apply", "-f", w.planFile("folders:\n  - name: app\ngroups:\n  - name: app:team\n"))

	// an auditor sees everything but the server refuses every change (it lacks
	// groups.write, and the privilege on the group), and the CLI says so
	if r := w.login("olu@tiny.example", []auth.Role{auth.RoleAuditor}, "approve"); r.code != 0 {
		t.Fatalf("login: %s %s", r.stdout, r.stderr)
	}
	before := w.domainEvents()
	file := w.planFile(fmt.Sprintf("groups:\n  - name: app:team\n    members:\n      add: [%d]\n", w.ids["bob"]))
	for _, cmd := range []string{"plan", "apply"} {
		r := w.run("groups", cmd, "-f", file)
		if r.code != exitError || !strings.Contains(r.stderr, "403") {
			t.Errorf("%s as a viewer: exit %d\nstdout: %s\nstderr: %s", cmd, r.code, r.stdout, r.stderr)
		}
	}
	if got := w.domainEvents(); got != before {
		t.Errorf("a refused plan wrote %d audit events", got-before)
	}
	// reading still works
	if r := w.run("groups", "ls"); r.code != 0 || !strings.Contains(r.stdout, "app:team") {
		t.Errorf("ls as an auditor: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
}

func TestGroupsCLI_Usage(t *testing.T) {
	w := newWorld(t)
	for _, args := range [][]string{{"groups"}, {"groups", "nope"}, {"groups", "plan"}, {"groups", "members", "add", "x"},
		{"groups", "export"}, {"groups", "show"}} {
		if r := w.run(args...); r.code != exitUsage {
			t.Errorf("%v: exit %d, want %d (stderr %q)", args, r.code, exitUsage, r.stderr)
		}
	}
	r := w.run("groups", "templates")
	if r.code != 0 || !strings.Contains(r.stdout, "application (version 1)") || !strings.Contains(r.stdout, "param admins") {
		t.Errorf("templates: %d %s %s", r.code, r.stdout, r.stderr)
	}
	// a bad plan is rejected before any request is made
	bad := w.planFile("groups:\n  - name: nofolder\n  - name: a:b\n    members: {add: [\"x\"]}\n")
	if r := w.run("groups", "plan", "-f", bad); r.code != exitUsage || !strings.Contains(r.stderr, "a group lives in a folder") {
		t.Errorf("bad plan: %d %s", r.code, r.stderr)
	}
}
