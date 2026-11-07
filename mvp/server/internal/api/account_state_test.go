package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const stateReason = `"reason":"leaver cleanup, ticket 42"`

func (h *provHarness) accountID(system, username string) int64 {
	h.t.Helper()
	var id int64
	testkit.Read(h.t, h.st, func(c *store.TenantTx) error {
		as, err := c.Accounts()
		for _, a := range as {
			if a.System == system && (username == "" || a.Username == username) {
				id = a.ID
				break
			}
		}
		return err
	})
	if id == 0 {
		h.t.Fatalf("no %s account %q", system, username)
	}
	return id
}

// accountRow is the account list row of one account.
func (h *provHarness) accountRow(id int64) map[string]any {
	h.t.Helper()
	for _, r := range h.c.json("GET", "/api/accounts", "", 200).([]any) {
		if m := r.(map[string]any); int64(m["id"].(float64)) == id {
			return m
		}
	}
	h.t.Fatalf("account %d not listed", id)
	return nil
}

// Disable and Enable go through the provisioning engine: the account keeps its status and shows "pending" until the
// re-read of the target confirms, then the status changes. Every request is audited.
func TestAccountState_DisableEnableClosesTheLoop(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"tok","write_back":true}`, 200)
	id := h.accountID("okta", h.alice)
	path := fmt.Sprintf("/api/accounts/%d/", id)

	v := h.c.json("POST", path+"disable", `{`+stateReason+`}`, http.StatusAccepted).(map[string]any)
	if v["status"] != "queued" || v["op_id"] == "" {
		t.Fatalf("disable = %v", v)
	}
	row := h.accountRow(id)
	if row["status"] != "active" || row["pending"] != "disable" {
		t.Errorf("before the re-read the row = %v", row)
	}
	// a second click joins the operation in flight; the opposite direction is refused
	if again := h.c.json("POST", path+"disable", `{`+stateReason+`}`, http.StatusAccepted).(map[string]any); again["status"] != "pending" || again["op_id"] != v["op_id"] {
		t.Errorf("second disable = %v", again)
	}
	if rec := h.c.do("POST", path+"enable", `{`+stateReason+`}`); rec.Code != http.StatusConflict {
		t.Errorf("enable while a disable is pending: %d %s", rec.Code, rec.Body)
	}
	for i := 0; i < 3; i++ {
		h.run()
	}
	if row = h.accountRow(id); row["status"] != "disabled" || row["pending"] != nil {
		t.Errorf("after the re-read the row = %v", row)
	}
	if _, active := h.fake.Active(h.alice); active {
		t.Error("the target still has the account active")
	}
	if rec := h.c.do("POST", path+"disable", `{`+stateReason+`}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "invalid_state") {
		t.Errorf("disable of a disabled account: %d %s", rec.Code, rec.Body)
	}

	// the admin who asked for the disable may not undo it (four eyes); a second admin may
	h.second().json("POST", path+"enable", `{`+stateReason+`}`, http.StatusAccepted)
	if row = h.accountRow(id); row["status"] != "disabled" || row["pending"] != "enable" {
		t.Errorf("enable pending row = %v", row)
	}
	for i := 0; i < 3; i++ {
		h.run()
	}
	if row = h.accountRow(id); row["status"] != "active" || row["pending"] != nil {
		t.Errorf("after enable the row = %v", row)
	}
	if _, active := h.fake.Active(h.alice); !active {
		t.Error("the target did not get the account back")
	}
	got := h.audit()
	for _, ev := range []string{"account.disable_requested", "account.enable_requested", "provision.enqueued"} {
		if !strings.Contains(got, ev) {
			t.Errorf("audit lacks %s: %s", ev, got)
		}
	}
}

// A target that acknowledges the write and does not apply it never confirms: the account keeps its status and a
// finding is raised.
func TestAccountState_MismatchKeepsStatusAndRaisesFinding(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok", Fault: fake.DropWrites})
	h.seedTarget()
	h.srv.Provisioning().Backoff = func(int) time.Duration { return 0 }
	h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"tok","write_back":true}`, 200)
	id := h.accountID("okta", h.alice)
	h.c.json("POST", fmt.Sprintf("/api/accounts/%d/disable", id), `{`+stateReason+`}`, http.StatusAccepted)
	for i := 0; i < 4; i++ {
		h.run()
	}
	if ops := h.ops("?status=mismatch"); len(ops) != 1 {
		t.Fatalf("ops = %v", h.ops(""))
	}
	if row := h.accountRow(id); row["status"] != "active" || row["pending"] != nil {
		t.Errorf("row = %v", row)
	}
	if fs := h.c.json("GET", "/api/provisioning/findings?status=open", "", 200).([]any); len(fs) != 1 || at(fs, 0, "code") != "verify_mismatch" {
		t.Errorf("findings = %v", fs)
	}
}

// Without write-back the call answers 409 target_read_only, one id at a time in the bulk form; ids that do not exist
// and ids that are not in the right state are reported per id, and nothing is queued for them.
func TestAccountState_BulkReportsPerID(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	alice := h.accountID("okta", h.alice)
	other := h.accountID("aws", "svc-etl")
	one := fmt.Sprintf("/api/accounts/%d/disable", alice)
	if rec := h.c.do("POST", one, `{`+stateReason+`}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "target_read_only") {
		t.Fatalf("read-only single: %d %s", rec.Code, rec.Body)
	}
	h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"tok","write_back":true}`, 200)

	body := fmt.Sprintf(`{"ids":[%d,%d,99999],%s}`, alice, other, stateReason)
	out := h.c.json("POST", "/api/accounts/disable", body, 200).(map[string]any)
	res := out["results"].([]any)
	if len(res) != 3 || out["accepted"].(float64) != 1 || out["failed"].(float64) != 2 {
		t.Fatalf("bulk = %v", out)
	}
	want := []string{"queued", "error", "error"}
	codes := []string{"", "target_read_only", "not_found"}
	for i, r := range res {
		m := r.(map[string]any)
		if m["status"] != want[i] || (codes[i] != "" && m["error"] != codes[i]) {
			t.Errorf("result %d = %v", i, m)
		}
	}
	// one audit event per id, and one for the refused single-form request before
	if n := strings.Count(h.audit(), "account.disable_requested"); n != 4 {
		t.Errorf("one audit event per id: %d", n)
	}
	// the connector kind decides whether an enable can run at all
	h.target(`{"kind":"okta","base_url":"https://acme.okta.com","token":"tok","write_back":true}`, 200)
	for _, r := range h.c.json("POST", "/api/accounts/enable", fmt.Sprintf(`{"ids":[%d],%s}`, alice, stateReason), 200).(map[string]any)["results"].([]any) {
		if m := r.(map[string]any); m["status"] != "error" {
			t.Errorf("enable on a connector without it = %v", m)
		}
	}
}

func TestAccountState_ValidatesInput(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = fmt.Sprint(i + 1)
	}
	for name, c := range map[string]struct{ path, body string }{
		"no ids":       {"/api/accounts/disable", `{"ids":[],` + stateReason + `}`},
		"101 ids":      {"/api/accounts/disable", `{"ids":[` + strings.Join(ids, ",") + `],` + stateReason + `}`},
		"duplicate":    {"/api/accounts/enable", `{"ids":[1,1],` + stateReason + `}`},
		"zero":         {"/api/accounts/enable", `{"ids":[0],` + stateReason + `}`},
		"short reason": {"/api/accounts/disable", `{"ids":[1],"reason":"x"}`},
		"unknown":      {"/api/accounts/disable", `{"ids":[1],` + stateReason + `,"force":true}`},
		"single short": {"/api/accounts/1/disable", `{"reason":"x"}`},
		"single none":  {"/api/accounts/1/enable", `{}`},
	} {
		if rec := h.c.do("POST", c.path, c.body); rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := h.c.do("POST", "/api/accounts/999999/disable", `{`+stateReason+`}`); rec.Code != http.StatusNotFound {
		t.Errorf("missing account: %d", rec.Code)
	}
}

// Only identities.contain (policy admin) with a fresh phishing-resistant sign-in may disable or enable an account.
func TestAccountState_PermissionAndStepUp(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"tok","write_back":true}`, 200)
	id := h.accountID("okta", h.alice)
	login := func(role auth.Role, c authtest.Ctx) client {
		l := signIn(t, h.st.DB, h.st.Tenant, authtest.User{Email: string(role) + "@larkspur.example", Roles: []auth.Role{role}}, c, testkit.Now)
		return client{t, l.Handler(h.srv.Handler())}
	}
	stale := authtest.Ctx{AAL: 2, Phr: true, AuthTime: testkit.Now.Add(-20 * time.Minute)}
	paths := []string{fmt.Sprintf("/api/accounts/%d/disable", id), fmt.Sprintf("/api/accounts/%d/enable", id), "/api/accounts/disable", "/api/accounts/enable"}
	bulk := fmt.Sprintf(`{"ids":[%d],%s}`, id, stateReason)
	for _, p := range paths {
		body := bulk
		if strings.Contains(p, fmt.Sprint(id)) {
			body = `{` + stateReason + `}`
		}
		for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RoleTenantAdmin} {
			if rec := login(role, authtest.Phr).do("POST", p, body); rec.Code != http.StatusForbidden {
				t.Errorf("%s as %s: %d %s", p, role, rec.Code, rec.Body)
			}
		}
		if rec := login(auth.RolePolicyAdmin, stale).do("POST", p, body); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s with a stale sign-in: %d %s", p, rec.Code, rec.Body)
		}
	}
	u := authtest.User{Email: "linked-policy@larkspur.example", Roles: []auth.Role{auth.RolePolicyAdmin},
		IdentityID: ensureIdentity(t, h.st.DB, h.st.Tenant, "emp-1030", "test-admin", testkit.Now)}
	rec := client{t, signIn(t, h.st.DB, h.st.Tenant, u, authtest.Phr, testkit.Now).Handler(h.srv.Handler())}.
		do("POST", paths[0], `{`+stateReason+`}`)
	var v map[string]any
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &v) != nil || v["status"] != "queued" {
		t.Errorf("policy admin: %d %s", rec.Code, rec.Body)
	}
}

// Account disable and enable keep the identity-level separation of duties: nobody changes an account of the identity
// their own Tessera user is linked to, an unlinked user is refused, and the accounts of a disabled identity come back
// only through Enable of the identity (four eyes), never one account at a time. Each refusal is audited, also in the
// single form.
func TestAccountState_SeparationOfDuties(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"tok","write_back":true}`, 200)
	id := h.accountID("okta", h.alice)
	var owner int64
	testkit.Read(t, h.st, func(c *store.TenantTx) error {
		a, err := c.Account(id)
		if err == nil && a.IdentityID != nil {
			owner = *a.IdentityID
		}
		return err
	})
	if owner == 0 {
		t.Fatal("alice's account has no identity")
	}
	as := func(u authtest.User) client {
		return client{t, signIn(t, h.st.DB, h.st.Tenant, u, authtest.Phr, testkit.Now).Handler(h.srv.Handler())}
	}
	self := as(authtest.User{Email: "alice-admin@larkspur.example", Roles: []auth.Role{auth.RolePolicyAdmin}, IdentityID: &owner})
	unlinked := as(authtest.User{Email: "unlinked@larkspur.example", Roles: []auth.Role{auth.RolePolicyAdmin}})
	one := fmt.Sprintf("/api/accounts/%d/", id)
	bulk := fmt.Sprintf(`{"ids":[%d],%s}`, id, stateReason)
	for name, c := range map[string]struct {
		cl         client
		path, body string
		code       int
		err        string
	}{
		"self single":     {self, one + "disable", `{` + stateReason + `}`, http.StatusForbidden, refuseSelfAccount},
		"unlinked single": {unlinked, one + "disable", `{` + stateReason + `}`, http.StatusForbidden, "actor_unlinked"},
		"self bulk":       {self, "/api/accounts/disable", bulk, http.StatusOK, refuseSelfAccount},
	} {
		rec := c.cl.do("POST", c.path, c.body)
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.err) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if row := h.accountRow(id); row["pending"] != nil {
		t.Errorf("a refused disable queued an operation: %v", row)
	}

	// the identity is disabled (its accounts with it): the linked admin may not enable one of its accounts
	testkit.Write(t, h.st, func(c *store.TenantTx) error {
		if err := c.DisableAccount(id); err != nil {
			return err
		}
		return c.SetIdentityStatus(owner, "disabled")
	})
	rec := h.c.do("POST", one+"enable", `{`+stateReason+`}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), refuseIdentityDisabled) {
		t.Errorf("enable an account of a disabled identity: %d %s", rec.Code, rec.Body)
	}
	for _, r := range h.c.json("POST", "/api/accounts/enable", bulk, 200).(map[string]any)["results"].([]any) {
		if m := r.(map[string]any); m["error"] != refuseIdentityDisabled {
			t.Errorf("bulk enable of a disabled identity's account = %v", m)
		}
	}
	if row := h.accountRow(id); row["pending"] != nil {
		t.Errorf("a refused enable queued an operation: %v", row)
	}
	// every refusal above is in the ledger, the single-form ones included
	got := h.audit()
	if n := strings.Count(got, "account.disable_requested"); n != 3 {
		t.Errorf("disable refusals audited: %d", n)
	}
	if n := strings.Count(got, "account.enable_requested"); n != 2 {
		t.Errorf("enable refusals audited: %d", n)
	}
}

// second is another linked admin, who may undo what the first asked for.
func (h *provHarness) second() client {
	h.t.Helper()
	id := ensureIdentity(h.t, h.st.DB, h.st.Tenant, "second-admin", "second-admin", testkit.Now)
	u := authtest.User{Email: "second-admin@larkspur.example", Roles: []auth.Role{auth.RolePolicyAdmin}, IdentityID: id}
	return client{h.t, signIn(h.t, h.st.DB, h.st.Tenant, u, authtest.Phr, testkit.Now).Handler(h.srv.Handler())}
}

// Enable of an account disabled through the account route needs a different person than the one who asked for the
// disable, single and bulk; the refusal is audited, and an account nobody asked to disable here has no one to differ from.
func TestAccountState_EnableNeedsFourEyes(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"tok","write_back":true}`, 200)
	id := h.accountID("okta", h.alice)
	path := fmt.Sprintf("/api/accounts/%d/", id)
	bulk := fmt.Sprintf(`{"ids":[%d],%s}`, id, stateReason)
	h.c.json("POST", path+"disable", `{`+stateReason+`}`, http.StatusAccepted)
	for i := 0; i < 3; i++ {
		h.run()
	}
	if row := h.accountRow(id); row["status"] != "disabled" {
		t.Fatalf("the disable did not complete: %v", row)
	}

	rec := h.c.do("POST", path+"enable", `{`+stateReason+`}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "four_eyes_required") {
		t.Errorf("same admin, single: %d %s", rec.Code, rec.Body)
	}
	for _, r := range h.c.json("POST", "/api/accounts/enable", bulk, 200).(map[string]any)["results"].([]any) {
		if m := r.(map[string]any); m["error"] != "four_eyes_required" || m["status"] != "error" {
			t.Errorf("same admin, bulk = %v", m)
		}
	}
	if row := h.accountRow(id); row["pending"] != nil || row["status"] != "disabled" {
		t.Errorf("a refused enable queued an operation: %v", row)
	}
	if n := strings.Count(h.audit(), "account.enable_requested"); n != 2 {
		t.Errorf("enable refusals audited: %d", n)
	}

	other := h.second()
	for _, r := range other.json("POST", "/api/accounts/enable", bulk, 200).(map[string]any)["results"].([]any) {
		if m := r.(map[string]any); m["status"] != "queued" {
			t.Errorf("second admin, bulk = %v", m)
		}
	}

	// disabled by something else (no request recorded here): any admin may enable
	bob := h.accountID("okta", h.bob)
	testkit.Write(t, h.st, func(c *store.TenantTx) error { return c.DisableAccount(bob) })
	h.c.json("POST", fmt.Sprintf("/api/accounts/%d/enable", bob), `{`+stateReason+`}`, http.StatusAccepted)
}

// A disable the deletion guard holds is pending for its account: asking again creates no second held item, so
// releasing the hold queues one disable. The opposite direction is refused while it waits.
func TestAccountState_HeldDisableIsNotDuplicated(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"tok","write_back":true}`, 200)
	id := h.accountID("okta", h.alice)
	path := fmt.Sprintf("/api/accounts/%d/", id)
	bulk := fmt.Sprintf(`{"ids":[%d],%s}`, id, stateReason)
	zero := 0
	testkit.Write(t, h.st, func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatAccounts, MaxCount: &zero, WindowMinutes: 60, Mode: deleteguard.ModeHoldAll}, nil, testkit.Now)
	})
	heldItems := func() (n int, hold string) {
		testkit.Read(t, h.st, func(c *store.TenantTx) error {
			hs, err := c.DeletionHolds("held", deleteguard.CatAccounts, 10, 0)
			for _, x := range hs {
				items, _ := c.DeletionHoldItems(x.ID)
				n += len(items)
				hold = x.ID
			}
			return err
		})
		return
	}

	if v := h.c.json("POST", path+"disable", `{`+stateReason+`}`, http.StatusAccepted).(map[string]any); v["status"] != "held" {
		t.Fatalf("first disable = %v", v)
	}
	if v := h.c.json("POST", path+"disable", `{`+stateReason+`}`, http.StatusAccepted).(map[string]any); v["status"] != "pending" {
		t.Errorf("second disable = %v", v)
	}
	for _, r := range h.c.json("POST", "/api/accounts/disable", bulk, 200).(map[string]any)["results"].([]any) {
		if m := r.(map[string]any); m["status"] != "pending" {
			t.Errorf("bulk disable of a held account = %v", m)
		}
	}
	if rec := h.second().do("POST", path+"enable", `{`+stateReason+`}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "operation_in_flight") {
		t.Errorf("enable while a disable is held: %d %s", rec.Code, rec.Body)
	}
	n, hold := heldItems()
	if n != 1 {
		t.Fatalf("held items = %d, want 1", n)
	}

	testkit.Write(t, h.st, func(c *store.TenantTx) error {
		_, err := deleteguard.Release(c, testkit.Now, hold, "approver", nil, deleteguard.Appliers{provision.ItemOp: provision.ReleaseHeld})
		return err
	})
	if got := h.ops(""); len(got) != 1 {
		t.Errorf("operations after the release = %d, want 1", len(got))
	}
	// released and queued: now in flight, still one operation
	if v := h.c.json("POST", path+"disable", `{`+stateReason+`}`, http.StatusAccepted).(map[string]any); v["status"] != "pending" || v["op_id"] == "" {
		t.Errorf("disable after the release = %v", v)
	}
	if got := h.ops(""); len(got) != 1 {
		t.Errorf("operations after asking again = %d, want 1", len(got))
	}
}
