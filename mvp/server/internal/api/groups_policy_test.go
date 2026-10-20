package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Policy groups as code (issue #52, GR-9) over the API.

func policyReq(files map[string]string, origin, commit string, full bool) string {
	var fs []map[string]string
	for path, cedar := range files {
		fs = append(fs, map[string]string{"path": path, "cedar": cedar})
	}
	b, _ := json.Marshal(map[string]any{"files": fs, "origin": origin, "commit": commit, "full": full})
	return string(b)
}

func policyCedar(group, permit, forbid string) string {
	s := `permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"` + group + `") when { ` + permit + ` };` + "\n"
	if forbid != "" {
		s += `forbid (principal, action == Tessera::Action::"member", resource == Tessera::Group::"` + group + `") when { ` + forbid + ` };` + "\n"
	}
	return s
}

func inGroup(name string) string { return `principal in Tessera::Group::"` + name + `"` }

func TestGroupsPolicyAPI(t *testing.T) {
	c, f := newGrp(t)
	alice, bob, carol := f.B.IDs["alice"], f.B.IDs["bob"], f.B.IDs["carol"]
	app := c.folder("", "app")
	staff, banned := c.group(app, "staff"), c.group(app, "banned")
	c.member(staff, alice)
	c.member(staff, bob)
	c.member(staff, carol)
	c.member(banned, bob)
	cedar := policyCedar("app:foo_user", inGroup("app:staff"), inGroup("app:banned"))
	files := map[string]string{"groups/app/foo_user.cedar": cedar}

	// validate: findings are an answer, not an error
	v := c.call("POST", "/api/groups/policy/validate", policyReq(files, "", "", false), 200)
	if v["valid"] != true || len(v["references"].([]any)) != 2 {
		t.Fatalf("validate = %v", v)
	}
	bad := c.call("POST", "/api/groups/policy/validate", policyReq(map[string]string{"a.cedar": "permit ("}, "", "", false), 200)
	if bad["valid"] != false || bad["diagnostics"].([]any)[0].(map[string]any)["code"] != "syntax" {
		t.Errorf("syntax finding = %v", bad)
	}
	missing := c.call("POST", "/api/groups/policy/validate", policyReq(map[string]string{"a.cedar": policyCedar("app:p", inGroup("app:nope"), "")}, "", "", false), 200)
	if missing["valid"] != false || missing["diagnostics"].([]any)[0].(map[string]any)["code"] != "unknown_group" {
		t.Errorf("unknown group = %v", missing)
	}

	// diff: who would join, without a write
	d := c.call("POST", "/api/groups/policy/diff", policyReq(files, "", "", false), 200)
	g0 := d["groups"].([]any)[0].(map[string]any)
	if g0["status"] != "new" || g0["added"] != float64(2) || g0["proposed"] != float64(2) {
		t.Errorf("diff = %v", d)
	}
	c.call("GET", "/api/groups/native?q=foo_user", "", 200)
	if items := c.call("GET", "/api/groups/native?q=foo_user", "", 200)["items"].([]any); len(items) != 0 {
		t.Error("a diff created a group")
	}

	// apply
	out := c.call("POST", "/api/groups/policy/apply", policyReq(files, "repo", "abc123", true), 200)
	res := out["groups"].([]any)[0].(map[string]any)
	if res["action"] != "created" || out["queued"] != false {
		t.Fatalf("apply = %v", out)
	}
	pid := res["id"].(string)
	g := c.call("GET", "/api/groups/"+pid, "", 200)
	if g["definition"] != "policy" || g["managed_by"] != "policy_repo" {
		t.Errorf("group = %v", g)
	}
	eff := c.call("GET", "/api/groups/"+pid+"/members?filter=effective", "", 200)
	if eff["total"] != float64(2) {
		t.Errorf("members = %v", eff)
	}
	src := c.call("GET", "/api/groups/"+pid+"/policy", "", 200)
	if src["commit"] != "abc123" || src["origin"] != "repo" || src["cedar"] != cedar || src["path"] != "groups/app/foo_user.cedar" {
		t.Errorf("policy = %v", src)
	}
	c.call("GET", "/api/groups/"+staff+"/policy", "", 404)
	c.call("GET", "/api/groups/not-an-id/policy", "", 404)

	// the same change is unchanged; a diff against it shows nothing
	again := c.call("POST", "/api/groups/policy/apply", policyReq(files, "repo", "abc123", true), 200)
	if again["groups"].([]any)[0].(map[string]any)["action"] != "unchanged" {
		t.Errorf("repeat = %v", again)
	}
	d = c.call("POST", "/api/groups/policy/diff", policyReq(files, "", "", true), 200)
	if d["groups"].([]any)[0].(map[string]any)["status"] != "unchanged" {
		t.Errorf("diff after apply = %v", d)
	}

	// findings of an apply are 422 with the diagnostics, and nothing changes
	rec := c.call("POST", "/api/groups/policy/apply", policyReq(map[string]string{"x.cedar": policyCedar("app:other", `context.x == "1"`, "")}, "repo", "c9", false), 422)
	if rec["error"] != "invalid_policy" || len(rec["diagnostics"].([]any)) == 0 {
		t.Errorf("422 = %v", rec)
	}
	c.call("POST", "/api/groups/policy/apply", policyReq(files, "repo", "bad commit", false), 422)
	c.call("POST", "/api/groups/policy/apply", `{"files":[],"unknown":1}`, 422)

	// the repository's group refuses every other writer
	for _, req := range []struct{ method, path, body string }{
		{"PATCH", "/api/groups/" + pid, `{"description":"x"}`},
		{"DELETE", "/api/groups/" + pid, ""},
		{"POST", "/api/groups/" + pid + "/members", fmt.Sprintf(`{"identity":%d}`, alice)},
		{"POST", "/api/groups/" + pid + "/move", `{"folder":"` + app + `"}`},
	} {
		if r := c.call(req.method, req.path, req.body, 409); r["error"] != "policy_managed" && r["error"] != "composite_no_members" {
			t.Errorf("%s %s: %v", req.method, req.path, r)
		}
	}
	if r := c.call("POST", "/api/groups/policy/apply", policyReq(files, "ui", "", false), 422); r["error"] != "invalid_policy" {
		t.Errorf("ui over repo = %v", r)
	}
	// a policy group cannot be made through the group routes
	c.call("POST", "/api/groups", `{"folder":"`+app+`","extension":"sneaky","definition":"policy"}`, 422)

	// a change: the denied group changes, a full sync with no files retires the group
	files2 := map[string]string{"groups/app/foo_user.cedar": policyCedar("app:foo_user", inGroup("app:staff"), "")}
	out = c.call("POST", "/api/groups/policy/apply", policyReq(files2, "repo", "def456", true), 200)
	if out["groups"].([]any)[0].(map[string]any)["action"] != "updated" {
		t.Errorf("update = %v", out)
	}
	if eff := c.call("GET", "/api/groups/"+pid+"/members?filter=effective", "", 200); eff["total"] != float64(3) {
		t.Errorf("members after the change = %v", eff)
	}
	out = c.call("POST", "/api/groups/policy/apply", policyReq(map[string]string{}, "repo", "fff789", true), 200)
	if out["groups"].([]any)[0].(map[string]any)["action"] != "removed" {
		t.Errorf("retire = %v", out)
	}

	// reindex
	rep := c.call("POST", "/api/groups/policy/reindex", "", 200)
	if rep["groups"] != float64(0) {
		t.Errorf("reindex = %v", rep)
	}
}

// TestGroupsPolicyAPI_Privileges: apply needs create on the folder and read on
// what the policy refers to; a policy group's admin may change it.
func TestGroupsPolicyAPI_Privileges(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	ref := e.admin.group(app, "ref")
	bob := e.user("bob", "bob")
	body := policyReq(map[string]string{"p.cedar": policyCedar("app:pol", inGroup("app:ref"), "")}, "repo", "c1", false)
	denied(t, bob, "POST", "/api/groups/policy/apply", body, "create")
	e.grant("/api/groups/folders/"+app, "create", "bob", "")
	// a group bob may not view is unknown to him (issue #387); once he may view it, reading it is what he lacks
	if r := bob.call("POST", "/api/groups/policy/apply", body, 422); r["error"] != "invalid_policy" {
		t.Errorf("hidden reference = %v", r)
	}
	e.grant("/api/groups/"+ref, "view", "bob", "")
	denied(t, bob, "POST", "/api/groups/policy/apply", body, "read")
	e.grant("/api/groups/"+ref, "read", "bob", "")
	out := bob.call("POST", "/api/groups/policy/apply", body, 200)
	pid := out["groups"].([]any)[0].(map[string]any)["id"].(string)
	// bob made it, so he administers it: he may change it, and must hold admin to
	body2 := policyReq(map[string]string{"p.cedar": policyCedar("app:pol", inGroup("app:ref")+" || "+inGroup("app:ref"), "")}, "repo", "c2", false)
	bob.call("POST", "/api/groups/policy/apply", body2, 200)
	other := e.user("other", "alice")
	e.grant("/api/groups/folders/"+app, "create", "alice", "")
	e.grant("/api/groups/"+ref, "read", "alice", "")
	denied(t, other, "POST", "/api/groups/policy/apply", body2, "admin")
	denied(t, other, "POST", "/api/groups/policy/diff", body2, "read")
	denied(t, other, "GET", "/api/groups/"+pid+"/policy", "", "read")
	// a full sync that would retire a group needs admin on it
	empty := policyReq(map[string]string{}, "repo", "c3", true)
	denied(t, other, "POST", "/api/groups/policy/apply", empty, "admin")
}

// A policy that names a group the caller may not view answers exactly as for a
// name that does not exist: no 403, no object_id (issue #387). A group the caller
// may view but not read keeps its 403.
func TestGroupsPolicyHiddenGroupIsUnknown(t *testing.T) {
	e := newPrivEnv(t)
	root := e.admin.folder("", "sec")
	secret := e.admin.group(root, "secret")
	e.grant("/api/groups/"+e.admin.group(root, "seen2"), "view", "bob", "")
	seen := "sec:seen2"
	e.grant("/api/groups/folders/"+root, "create", "bob", "")
	bob := e.user("bob", "bob")
	body := func(name string) string {
		return policyReq(map[string]string{"groups/sec/p.cedar": policyCedar("sec:p", inGroup(name), "")}, "", "", false)
	}
	for _, route := range []string{"validate", "diff", "apply"} {
		t.Run(route, func(t *testing.T) {
			path := "/api/groups/policy/" + route
			hidden := bob.do("POST", path, body("sec:secret"))
			missing := bob.do("POST", path, body("sec:nosuch"))
			norm := func(s, name string) string { return strings.ReplaceAll(s, name, "NAME") }
			if hidden.Code != missing.Code || norm(hidden.Body.String(), "sec:secret") != norm(missing.Body.String(), "sec:nosuch") {
				t.Errorf("hidden = %d %s, missing = %d %s", hidden.Code, hidden.Body, missing.Code, missing.Body)
			}
			if strings.Contains(hidden.Body.String(), secret) || strings.Contains(hidden.Body.String(), "privilege_required") {
				t.Errorf("the answer for a hidden group leaks it: %s", hidden.Body)
			}
			if !strings.Contains(hidden.Body.String(), "unknown_group") {
				t.Errorf("want an unknown_group finding: %d %s", hidden.Code, hidden.Body)
			}
			// viewable, not readable: still 403
			denied(t, bob, "POST", path, body(seen), "read")
		})
	}
}

// TestGroupsPolicyDefinedHiddenGroupNoID: a change that defines a group the
// caller may not view is refused without the group's id (#387).
func TestGroupsPolicyDefinedHiddenGroupNoID(t *testing.T) {
	e := newPrivEnv(t)
	root := e.admin.folder("", "sec")
	secret := e.admin.group(root, "secret")
	seen := e.admin.group(root, "seen3")
	e.grant("/api/groups/"+seen, "view", "bob", "")
	e.grant("/api/groups/folders/"+root, "create", "bob", "")
	bob := e.user("bob", "bob")
	body := func(name string) string {
		return policyReq(map[string]string{"groups/sec/p.cedar": policyCedar(name, `principal has department && principal.department == "x"`, "")}, "", "", false)
	}
	for _, route := range []string{"diff", "apply"} {
		t.Run(route, func(t *testing.T) {
			path := "/api/groups/policy/" + route
			rec := bob.do("POST", path, body("sec:secret"))
			if rec.Code != 403 || strings.Contains(rec.Body.String(), secret) {
				t.Errorf("defining a hidden group: %d %s", rec.Code, rec.Body)
			}
			// a group the caller can view still names itself in the refusal
			rec = bob.do("POST", path, body("sec:seen3"))
			if rec.Code != 403 || !strings.Contains(rec.Body.String(), seen) {
				t.Errorf("defining a viewable group: %d %s", rec.Code, rec.Body)
			}
		})
	}
}
