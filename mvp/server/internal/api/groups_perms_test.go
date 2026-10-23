package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Permissions and limits (issue #62, GR-19).

func TestGroupsPermissionsAPI(t *testing.T) {
	c, f := newGrp(t)
	alice, bob := f.B.IDs["alice"], f.B.IDs["bob"]
	app := c.folder("", "app")
	role := c.group(app, "payroll")
	c.member(role, alice)

	perm := c.attrDef(app, "perms", `"attr_type":"perm","multi_assign":true,"assign_to":["group","membership"]`)
	ledger, entry := c.attrName(perm, "ledger"), c.attrName(perm, "entry")
	c.call("PUT", "/api/groups/attr-names/"+ledger+"/implies", `{"implies":["`+entry+`"]}`, 200)
	read := c.call("POST", "/api/groups/attr-defs/"+perm+"/actions", `{"name":"read"}`, 201)["id"].(string)
	write := c.call("POST", "/api/groups/attr-defs/"+perm+"/actions", `{"name":"write"}`, 201)["id"].(string)
	c.call("PUT", "/api/groups/attr-defs/"+perm+"/actions/"+write+"/implies", `{"implies":["`+read+`"]}`, 200)
	lim := c.attrDef(app, "limits", `"attr_type":"limit","value_type":"integer","multi_valued":true,"assign_to":["assignment"]`)
	amount := c.attrName(lim, "amountLessThan")
	plain := c.attrDef(app, "plain", `"assign_to":["group"]`)
	c.attrName(plain, "x")

	granted := c.call("POST", "/api/groups/attr-assignments", `{"name":"`+ledger+`","action":"write","owner_type":"group","owner":"`+role+`"}`, 201)["id"].(string)
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+amount+`","owner_type":"assignment","owner":"`+granted+`","values":[1000]}`, 201)

	check := func(who int64, resource, action, extra string, want int) map[string]any {
		return c.call("GET", fmt.Sprintf("/api/groups/permissions/check?identity=%d&resource=%s&action=%s%s", who, resource, action, extra), "", want)
	}
	// the limit holds, fails, and is missing
	if got := check(alice, "app:perms:entry", "read", "&ctx.amount=999", 200); got["allowed"] != true || got["reason"] != "allowed" {
		t.Errorf("limit holds: %v", got)
	}
	got := check(alice, "app:perms:entry", "read", "&ctx.amount=1000", 200)
	if got["allowed"] != false || got["reason"] != "no_permission" || len(got["limits_failed"].([]any)) != 1 {
		t.Errorf("limit fails: %v", got)
	}
	if got := check(alice, "app:perms:entry", "read", "", 200); got["allowed"] != false {
		t.Errorf("amount missing: %v", got)
	}
	if got := check(bob, "app:perms:entry", "read", "&ctx.amount=1", 200); got["allowed"] != false {
		t.Errorf("not in the role: %v", got)
	}
	// errors
	check(alice, "app:perms:nothing", "read", "", 404)
	check(alice, "app:perms:entry", "fly", "", 404)
	check(alice, "app:plain:x", "read", "", 422)
	check(alice, "app:perms:entry", "read", "&ctx.bad-name=1", 422)
	check(alice, "app:perms:entry", "read", "&as_of=tomorrow", 422)
	check(alice, "app:perms:entry", "read", "&as_of="+url.QueryEscape(storetest.Now.Add(time.Hour).Format(time.RFC3339)), 422)
	c.call("GET", "/api/groups/permissions/check?identity=x&resource=a", "", 422)
	c.call("GET", "/api/groups/permissions/check?identity=999999&resource=a:b:c", "", 404)
	c.call("GET", fmt.Sprintf("/api/groups/permissions/check?identity=%d", alice), "", 422)
	// another tenant's identity looks nonexistent
	c.call("GET", fmt.Sprintf("/api/groups/permissions/effective?identity=%d", f.A.IDs["alice"]), "", 404)

	// effective: ledger and entry, write and read, all conditional
	eff := c.call("GET", fmt.Sprintf("/api/groups/permissions/effective?identity=%d", alice), "", 200)
	items := eff["permissions"].([]any)
	if len(items) != 4 || eff["truncated"] != false {
		t.Fatalf("effective = %v", eff)
	}
	for _, it := range items {
		m := it.(map[string]any)
		if m["allowed"] != true || m["conditional"] != true || len(m["via"].([]any)) != 1 {
			t.Errorf("effective item = %v", m)
		}
	}
	c.call("GET", fmt.Sprintf("/api/groups/permissions/effective?identity=%d&as_of=%s", alice, url.QueryEscape(storetest.Now.Add(-time.Hour).Format(time.RFC3339))), "", 200)

	// the role's assignments and the Cedar text
	rp := c.call("GET", "/api/groups/"+role+"/permissions", "", 200)["permissions"].([]any)
	if len(rp) != 1 || rp[0].(map[string]any)["resource"] != "app:perms:ledger" || len(rp[0].(map[string]any)["limits"].([]any)) != 1 {
		t.Errorf("role permissions = %v", rp)
	}
	c.call("GET", "/api/groups/nope/permissions", "", 404)
	pol := c.call("GET", "/api/groups/permissions/cedar", "", 200)["policy"].(string)
	for _, want := range []string{`principal in Tessera::Group::"app:payroll"`, `resource in Tessera::Resource::"app:perms:ledger"`, `context.amount < 1000`} {
		if !strings.Contains(pol, want) {
			t.Errorf("cedar lacks %q:\n%s", want, pol)
		}
	}

	// export, remove, import: the same document comes back
	doc := c.call("GET", "/api/groups/permissions/export", "", 200)
	c.call("DELETE", "/api/groups/attr-assignments/"+granted, "", 200)
	if n := len(c.call("GET", "/api/groups/permissions/export", "", 200)["permissions"].([]any)); n != 0 {
		t.Fatalf("after delete: %d", n)
	}
	body := permJSON(t, doc)
	if res := c.call("POST", "/api/groups/permissions/import", body, 200); res["created"] != float64(1) || res["replaced"] != float64(0) {
		t.Errorf("import = %v", res)
	}
	if res := c.call("POST", "/api/groups/permissions/import", body, 200); res["unchanged"] != float64(1) || res["created"] != float64(0) {
		t.Errorf("re-import = %v", res)
	}
	if again := c.call("GET", "/api/groups/permissions/export", "", 200); permJSON(t, again) != body {
		t.Errorf("round trip changed the export:\n%s\n%s", body, permJSON(t, again))
	}
	// a bad document applies nothing and says why; unknown fields are refused
	bad := c.call("POST", "/api/groups/permissions/import", `{"permissions":[{"role":"app:nobody","resource":"app:perms:entry","action":"read"}]}`, 422)
	if bad["error"] != "invalid_import" || len(bad["errors"].([]any)) != 1 {
		t.Errorf("bad import = %v", bad)
	}
	c.call("POST", "/api/groups/permissions/import", `{"permissions":[],"extra":1}`, 422)
	c.call("POST", "/api/groups/permissions/import", ``, 422)
}

func permJSON(t *testing.T, v map[string]any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
