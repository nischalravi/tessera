package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Acceptance tests of the proposing resources (server issue #721) against a real `tessera serve` and a real dev IdP. The
// provider holds a machine client that may only propose; two people (Alice and Ivan, both tenant admins, signed in with a
// passkey through the dev IdP) grant it the config.propose scope and approve what it proposes, and the tests watch the
// provider wait for them. Ivan owns the machine client, so Ivan can never approve its proposals: Alice does.

// human is a person signed in through the dev IdP: a session cookie and the CSRF token its mutating calls carry.
type human struct {
	t    *testing.T
	ts   *testServer
	http *http.Client
	csrf string
}

var idpReqRE = regexp.MustCompile(`name="req" value="([^"]+)"`)

// signIn runs the browser sign-in as the dev IdP user sub, with a passkey (phishing-resistant, so a fresh step-up).
func (ts *testServer) signIn(t *testing.T, sub string) *human {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &human{t: t, ts: ts, http: &http.Client{Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	step := func(res *http.Response, err error) (*http.Response, []byte) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return res, b
	}
	res, b := step(h.http.Get(ts.URL + "/api/auth/login?tenant=" + ts.Tenant + "&return_to=/")) // #nosec G107 -- loopback test server
	if res.StatusCode != http.StatusFound {
		t.Fatalf("login start: %d %s", res.StatusCode, b)
	}
	res, b = step(h.http.Get(res.Header.Get("Location"))) // #nosec G107 -- the loopback dev IdP
	m := idpReqRE.FindSubmatch(b)
	if res.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("dev IdP sign-in page: %d %s", res.StatusCode, b)
	}
	res, b = step(h.http.PostForm(ts.IdPURL+"/authorize", url.Values{"req": {html.UnescapeString(string(m[1]))},
		"choice": {sub + " passkey"}, "profile": {"okta"}}))
	if res.StatusCode != http.StatusSeeOther && res.StatusCode != http.StatusFound {
		t.Fatalf("dev IdP sign-in: %d %s", res.StatusCode, b)
	}
	cb, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	res, b = step(h.http.Get(ts.URL + cb.RequestURI())) // #nosec G107 -- loopback test server
	if res.StatusCode != http.StatusFound {
		t.Fatalf("login callback: %d %s", res.StatusCode, b)
	}
	res, b = step(h.http.Get(ts.URL + "/api/auth/session")) // #nosec G107 -- loopback test server
	var sess struct {
		CSRF string `json:"csrf_token"`
	}
	if res.StatusCode != http.StatusOK || json.Unmarshal(b, &sess) != nil || sess.CSRF == "" {
		t.Fatalf("session: %d %s", res.StatusCode, b)
	}
	h.csrf = sess.CSRF
	return h
}

// call makes an API request as the person and decodes a JSON object answer.
func (h *human) call(method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.ts.URL+path, rd) // #nosec G107 -- loopback test server
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Origin", h.ts.URL)
	req.Header.Set("X-Tessera-CSRF", h.csrf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	if v == nil {
		v = map[string]any{"raw": string(b)}
	}
	return res.StatusCode, v
}

func (h *human) must(method, path string, body any, want int) map[string]any {
	h.t.Helper()
	code, v := h.call(method, path, body)
	if code != want {
		h.t.Fatalf("%s %s: %d %v, want %d", method, path, code, v, want)
	}
	return v
}

// pending waits for a pending config.proposal of the given kind to show up in the admin center and returns it.
func (h *human) pending(typ string, known map[string]bool) map[string]any {
	h.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		v := h.must("GET", "/api/admin/change-requests?status=pending_approval", nil, 200)
		rows, _ := v["change_requests"].([]any)
		for _, r := range rows {
			c := r.(map[string]any)
			if c["type"] == typ && !known[c["id"].(string)] {
				known[c["id"].(string)] = true
				return c
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	h.t.Fatalf("no pending %s appeared", typ)
	return nil
}

func (h *human) approve(c map[string]any) map[string]any {
	h.t.Helper()
	return h.must("POST", "/api/admin/change-requests/"+c["id"].(string)+"/approve", map[string]string{"payload_hash": c["payload_hash"].(string)}, 200)
}

// applyAsync runs a resource apply in the background, so the test can act as the approver while the provider waits.
type applied struct {
	state tftypes.Value
	diags []*tfprotov6.Diagnostic
}

func applyAsync(p *protocol, name string, vals map[string]any, prior tftypes.Value) <-chan applied {
	out := make(chan applied, 1)
	go func() {
		st, d := p.apply(name, vals, prior)
		out <- applied{st, d}
	}()
	return out
}

func within(t *testing.T, ch <-chan applied, d time.Duration) applied {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(d):
		t.Fatalf("the apply did not finish within %s", d)
	}
	return applied{}
}

func notDone(t *testing.T, ch <-chan applied, d time.Duration, why string) {
	t.Helper()
	select {
	case a := <-ch:
		t.Fatalf("the apply finished (%s) while %s: %s", diagText(a.diags), why, a.state)
	case <-time.After(d):
	}
}

func numSet(ids ...int64) tftypes.Value {
	els := make([]tftypes.Value, len(ids))
	for i, id := range ids {
		els[i] = tftypes.NewValue(tftypes.Number, big.NewFloat(float64(id)))
	}
	return tftypes.NewValue(tftypes.Set{ElementType: tftypes.Number}, els)
}

func (ts *testServer) proposerConfig(clientID string, extra map[string]any) map[string]any {
	c := ts.providerConfig(clientID, clientID == ts.DPoPID)
	c["poll_interval"], c["wait_timeout"] = "200ms", "2m"
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestAcc_Proposals(t *testing.T) {
	ts := startTestServerWithIdP(t)
	alice, ivan := ts.signIn(t, "00u-alice-admin"), ts.signIn(t, "00u-ivan-admin2")
	seen := map[string]bool{}
	const ruleRes = "tessera_alert_rule"
	rule := map[string]any{"rule_id": "signin_failures", "enabled": true, "severity": "critical", "threshold": 3, "window_minutes": 20}

	// 1. the client holds no config.propose scope, so the server refuses: a proposal is not a way around a missing grant
	p := newProtocol(t)
	if d := p.configure(ts.proposerConfig(ts.DPoPID, nil)); len(d) > 0 {
		t.Fatalf("configure: %s", diagText(d))
	}
	null := tftypes.NewValue(p.resourceType(ruleRes), nil)
	if _, d := p.apply(ruleRes, rule, null); !strings.Contains(diagText(d), "config.propose") {
		t.Fatalf("a client without the scope: %q", diagText(d))
	}

	// 2. the scope needs two admins: Ivan asks, Alice approves; Ivan cannot approve his own request
	grant := ivan.must("POST", "/api/admin/change-requests", map[string]any{"type": "api_client.propose.grant",
		"payload": map[string]string{"client_id": ts.DPoPID}}, 201)
	if code, v := ivan.call("POST", "/api/admin/change-requests/"+grant["id"].(string)+"/approve", map[string]string{"payload_hash": grant["payload_hash"].(string)}); code != 403 || v["error"] != "self_approval_refused" {
		t.Fatalf("the requesting admin approved the grant: %d %v", code, v)
	}
	if v := alice.approve(grant); v["status"] != "applied" {
		t.Fatalf("grant after the second admin: %v", v)
	}

	// 3. alert rule: the apply waits for a person; the owner cannot approve; Alice does; then it is applied
	p = newProtocol(t) // a new token: the scope is in the client's registration now
	if d := p.configure(ts.proposerConfig(ts.DPoPID, nil)); len(d) > 0 {
		t.Fatalf("configure: %s", diagText(d))
	}
	done := applyAsync(p, ruleRes, rule, null)
	c := alice.pending("config.proposal", seen)
	notDone(t, done, 1*time.Second, "nobody had approved")
	if c["proposed_by_client"] != ts.DPoPID {
		t.Fatalf("the admin view does not name the client: %v", c)
	}
	if code, v := ivan.call("POST", "/api/admin/change-requests/"+c["id"].(string)+"/approve", map[string]string{"payload_hash": c["payload_hash"].(string)}); code != 403 || v["error"] != "self_approval_refused" {
		t.Fatalf("the client's owner approved its proposal: %d %v", code, v)
	}
	notDone(t, done, 500*time.Millisecond, "its owner had been refused")
	alice.approve(c)
	res := within(t, done, 30*time.Second)
	if len(res.diags) > 0 {
		t.Fatalf("alert rule apply: %s", diagText(res.diags))
	}
	a := attrs(t, res.state)
	if str(t, a["id"]) != "signin_failures" || str(t, a["change_id"]) != c["id"] || !strings.Contains(str(t, a["change_url"]), "/admin/change-requests?id="+c["id"].(string)) {
		t.Fatalf("alert rule state: %v", res.state)
	}
	// the change was applied by the approval, and the audit trail names the client
	if v := alice.must("GET", "/api/admin/change-requests/"+c["id"].(string), nil, 200); v["status"] != "applied" {
		t.Fatalf("change after approval: %v", v)
	}

	// 4. a refusal: Alice rejects, and the apply fails with the change URL
	rule["threshold"] = 4
	done = applyAsync(p, ruleRes, rule, res.state)
	c = alice.pending("config.proposal", seen)
	alice.must("POST", "/api/admin/change-requests/"+c["id"].(string)+"/reject", nil, 200)
	res2 := within(t, done, 30*time.Second)
	if txt := diagText(res2.diags); !strings.Contains(txt, "was rejected") || !strings.Contains(txt, "/admin/change-requests?id="+c["id"].(string)) {
		t.Fatalf("a rejected proposal: %q", txt)
	}

	// 5. a timeout: nobody approves, the apply fails with the URL and the change stays pending
	short := newProtocol(t)
	if d := short.configure(ts.proposerConfig(ts.DPoPID, map[string]any{"wait_timeout": "1s"})); len(d) > 0 {
		t.Fatalf("configure: %s", diagText(d))
	}
	rule["threshold"] = 5
	_, d := short.apply(ruleRes, rule, res.state)
	if txt := diagText(d); !strings.Contains(txt, "nobody approved it within 1s") || !strings.Contains(txt, "/admin/change-requests?id=") {
		t.Fatalf("a timed-out proposal: %q", txt)
	}
	late := alice.pending("config.proposal", seen)
	if late["status"] != "pending_approval" {
		t.Fatalf("a timed-out proposal is not left pending: %v", late)
	}
	alice.must("POST", "/api/admin/change-requests/"+late["id"].(string)+"/cancel", nil, 200)

	// 6. the same wait for each of the other resources: create, approve, read back, update
	ents, d := p.readData("tessera_entitlements", map[string]any{"system": "aws"})
	if len(d) > 0 {
		t.Fatalf("entitlements: %s", diagText(d))
	}
	var els []tftypes.Value
	_ = ents["entitlements"].As(&els)
	groupID := num(t, attrs(t, els[0])["id"])

	approveNext := func(done <-chan applied) applied {
		t.Helper()
		alice.approve(alice.pending("config.proposal", seen))
		r := within(t, done, 30*time.Second)
		if len(r.diags) > 0 {
			t.Fatalf("apply: %s", diagText(r.diags))
		}
		return r
	}

	t.Run("business role", func(t *testing.T) {
		const res = "tessera_business_role"
		cfg := map[string]any{"key": "tf-role", "name": "TF role", "risk": "low", "requestable": true, "entitlement_group_ids": numSet(groupID)}
		st := approveNext(applyAsync(p, res, cfg, tftypes.NewValue(p.resourceType(res), nil))).state
		a := attrs(t, st)
		if !uuidRE.MatchString(str(t, a["id"])) || num(t, a["version"]) != 1 || str(t, a["change_id"]) == "<null>" {
			t.Fatalf("created role: %v", st)
		}
		if again, d := p.read(res, st); len(d) > 0 || !again.Equal(st) {
			t.Fatalf("refresh changed the state: %s\n%v\n%v", diagText(d), st, again)
		}
		cfg["name"] = "TF role (renamed)"
		st2 := approveNext(applyAsync(p, res, cfg, st)).state
		a2 := attrs(t, st2)
		if str(t, a2["id"]) != str(t, a["id"]) || num(t, a2["version"]) != 2 || str(t, a2["name"]) != "TF role (renamed)" {
			t.Fatalf("updated role: %v", st2)
		}
		d := p.destroy(res, st2)
		if diagText(d) != "" || len(d) != 1 || d[0].Severity != tfprotov6.DiagnosticSeverityWarning {
			t.Fatalf("destroy should only warn that the role stays: %v", d)
		}
		// destroy only forgets it: the role is still there
		if v, d := p.read(res, st2); len(d) > 0 || v.IsNull() {
			t.Fatalf("the role is gone after destroy: %v %s", v, diagText(d))
		}
	})
	t.Run("sod ruleset", func(t *testing.T) {
		const res = "tessera_sod_ruleset"
		cfg := map[string]any{"key": "tf-sod", "name": "TF ruleset", "description": "from terraform"}
		st := approveNext(applyAsync(p, res, cfg, tftypes.NewValue(p.resourceType(res), nil))).state
		a := attrs(t, st)
		if !uuidRE.MatchString(str(t, a["id"])) || num(t, a["version"]) != 1 || !a["enabled"].Equal(tftypes.NewValue(tftypes.Bool, true)) {
			t.Fatalf("created ruleset: %v", st)
		}
		cfg["enabled"] = false
		st2 := approveNext(applyAsync(p, res, cfg, st)).state
		if a2 := attrs(t, st2); num(t, a2["version"]) != 2 || !a2["enabled"].Equal(tftypes.NewValue(tftypes.Bool, false)) {
			t.Fatalf("updated ruleset: %v", st2)
		}
	})
	t.Run("catalog item", func(t *testing.T) {
		const res = "tessera_catalog_item"
		cfg := map[string]any{"group_id": int(groupID), "requestable": true, "risk": "low", "description": "from terraform",
			"default_hours": tftypes.NewValue(tftypes.Number, big.NewFloat(8)), "max_hours": tftypes.NewValue(tftypes.Number, big.NewFloat(24))}
		st := approveNext(applyAsync(p, res, cfg, tftypes.NewValue(p.resourceType(res), nil))).state
		if a := attrs(t, st); str(t, a["id"]) != fmt.Sprint(groupID) || str(t, a["change_id"]) == "<null>" {
			t.Fatalf("catalog item: %v", st)
		}
		// the server lets a machine client read no catalog item: refresh keeps what was applied
		if again, d := p.read(res, st); len(d) > 0 || !again.Equal(st) {
			t.Fatalf("refresh: %s", diagText(d))
		}
		cfg["risk"] = "high"
		st2 := approveNext(applyAsync(p, res, cfg, st)).state
		if str(t, attrs(t, st2)["risk"]) != "high" {
			t.Fatalf("updated catalog item: %v", st2)
		}
	})

	// the new policy kinds (server issue #719): each is proposed, approved by a person, read back, updated and imported
	idents, d := p.readData("tessera_identities", map[string]any{"query": "ingrid"})
	if len(d) > 0 {
		t.Fatalf("identities: %s", diagText(d))
	}
	var ils []tftypes.Value
	_ = idents["identities"].As(&ils)
	ownerID := num(t, attrs(t, ils[0])["id"])
	importVerifies := func(t *testing.T, res string, st tftypes.Value) {
		t.Helper()
		imp, d := p.importState(res, str(t, attrs(t, st)["id"]))
		if len(d) > 0 {
			t.Fatalf("import: %s", diagText(d))
		}
		got, d := p.read(res, imp)
		if len(d) > 0 {
			t.Fatalf("read after import: %s", diagText(d))
		}
		want, gotA := attrs(t, st), attrs(t, got)
		for k, v := range want {
			if k == "change_id" || k == "change_url" || k == "note" {
				continue // the proposal's own bookkeeping is not on the server
			}
			if !gotA[k].Equal(v) {
				t.Fatalf("import changed %s: %v vs %v", k, gotA[k], v)
			}
		}
	}
	t.Run("birthright rule", func(t *testing.T) {
		const res = "tessera_birthright_rule"
		cond := `{"attr":"identity.department","op":"eq","value":"Finance"}`
		cfg := map[string]any{"name": "TF finance staff", "description": "from terraform", "condition_json": cond}
		st := approveNext(applyAsync(p, res, cfg, tftypes.NewValue(p.resourceType(res), nil))).state
		a := attrs(t, st)
		if !uuidRE.MatchString(str(t, a["id"])) || num(t, a["version"]) != 1 || str(t, a["condition_json"]) != cond {
			t.Fatalf("created rule: %v", st)
		}
		if again, d := p.read(res, st); len(d) > 0 || !again.Equal(st) {
			t.Fatalf("refresh changed the state: %s\n%v\n%v", diagText(d), st, again)
		}
		importVerifies(t, res, st)
		cfg["condition_json"] = `{"any":[{"attr":"identity.department","op":"eq","value":"Finance"},{"attr":"identity.department","op":"eq","value":"Legal"}]}`
		st2 := approveNext(applyAsync(p, res, cfg, st)).state
		if a2 := attrs(t, st2); str(t, a2["id"]) != str(t, a["id"]) || num(t, a2["version"]) != 2 {
			t.Fatalf("updated rule: %v", st2)
		}
		// a bad condition is refused by the server before anyone is asked
		cfg["condition_json"] = `{"attr":"nope","op":"eq","value":1}`
		if _, d := p.apply(res, cfg, st2); !strings.Contains(diagText(d), "condition:") {
			t.Fatalf("a bad condition: %q", diagText(d))
		}
		if d := p.validate(res, map[string]any{"name": "x", "condition_json": "[1]"}); !strings.Contains(diagText(d), "JSON object") {
			t.Fatalf("a JSON array as a condition: %q", diagText(d))
		}
	})
	t.Run("mitigating control", func(t *testing.T) {
		const res = "tessera_mitigating_control"
		cfg := map[string]any{"name": "TF monthly review", "owner_identity_id": int(ownerID), "type": "detective", "frequency": "monthly",
			"evidence_requirement": "signed report"}
		st := approveNext(applyAsync(p, res, cfg, tftypes.NewValue(p.resourceType(res), nil))).state
		a := attrs(t, st)
		if !uuidRE.MatchString(str(t, a["id"])) || num(t, a["version"]) != 1 || num(t, a["owner_identity_id"]) != ownerID {
			t.Fatalf("created control: %v", st)
		}
		if again, d := p.read(res, st); len(d) > 0 || !again.Equal(st) {
			t.Fatalf("refresh changed the state: %s", diagText(d))
		}
		importVerifies(t, res, st)
		cfg["frequency"] = "weekly"
		st2 := approveNext(applyAsync(p, res, cfg, st)).state
		if a2 := attrs(t, st2); num(t, a2["version"]) != 2 || str(t, a2["frequency"]) != "weekly" {
			t.Fatalf("updated control: %v", st2)
		}
		cfg["owner_identity_id"] = 99999999
		if _, d := p.apply(res, cfg, st2); !strings.Contains(diagText(d), "owner_not_found") {
			t.Fatalf("an unknown owner: %q", diagText(d))
		}
	})
	t.Run("approval policy", func(t *testing.T) {
		const res = "tessera_approval_policy"
		steps := `[{"approver":"decider","id":"d","type":"approval"}]`
		cfg := map[string]any{"name": "TF one step", "scope": "access", "steps_json": steps}
		st := approveNext(applyAsync(p, res, cfg, tftypes.NewValue(p.resourceType(res), nil))).state
		a := attrs(t, st)
		if !uuidRE.MatchString(str(t, a["id"])) || num(t, a["version"]) != 1 || str(t, a["steps_json"]) != steps {
			t.Fatalf("created policy: %v", st)
		}
		if again, d := p.read(res, st); len(d) > 0 || !again.Equal(st) {
			t.Fatalf("refresh changed the state: %s\n%v\n%v", diagText(d), st, again)
		}
		importVerifies(t, res, st)
		tgtType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"kind": tftypes.String, "target_id": tftypes.String}}
		cfg["targets"] = tftypes.NewValue(tftypes.Set{ElementType: tgtType}, []tftypes.Value{tftypes.NewValue(tgtType,
			map[string]tftypes.Value{"kind": tftypes.NewValue(tftypes.String, "request_type"), "target_id": tftypes.NewValue(tftypes.String, "access")})})
		cfg["steps_json"] = `[{"approver":"manager","id":"m","type":"approval"},{"approver":"decider","id":"d","type":"approval"}]`
		st2 := approveNext(applyAsync(p, res, cfg, st)).state
		a2 := attrs(t, st2)
		var ts []tftypes.Value
		_ = a2["targets"].As(&ts)
		if num(t, a2["version"]) != 2 || len(ts) != 1 {
			t.Fatalf("updated policy: %v", st2)
		}
		importVerifies(t, res, st2)
	})

	// the resources that carry secrets (server issue #719): the secret is write-only, so it is in no plan, no state, no change
	// request an admin reads and no log; a changed *_version sends a new one and an unchanged one leaves the server's alone
	const (
		connSecret = "PLAINTEXT-connector-secret-1"
		hookSecret = "PLAINTEXT-signing-secret-0001"
		hookURL    = "https://hooks.example.com/services/PLAINTEXT-url-token"
		hecToken   = "PLAINTEXT-hec-token-1"
	)
	// approveHiding approves the next pending proposal after checking that nothing an admin can read holds a secret
	approveHiding := func(t *testing.T, done <-chan applied, plaintexts ...string) applied {
		t.Helper()
		c := alice.pending("config.proposal", seen)
		full := alice.must("GET", "/api/admin/change-requests/"+c["id"].(string), nil, 200)
		for _, v := range []any{c, full} {
			raw, _ := json.Marshal(v)
			for _, pt := range plaintexts {
				if strings.Contains(string(raw), pt) {
					t.Fatalf("the change request shows %q: %s", pt, raw)
				}
			}
		}
		alice.approve(c)
		r := within(t, done, 30*time.Second)
		if len(r.diags) > 0 {
			t.Fatalf("apply: %s", diagText(r.diags))
		}
		return r
	}
	notInState := func(t *testing.T, st tftypes.Value, plaintexts ...string) {
		t.Helper()
		for _, pt := range plaintexts {
			if strings.Contains(st.String(), pt) {
				t.Fatalf("the state holds %q: %s", pt, st)
			}
		}
	}
	t.Run("connection", func(t *testing.T) {
		const res = "tessera_connection"
		cfg := map[string]any{"name": "TF okta", "connector_type": "okta", "config_json": `{"org_url":"https://tf.okta.com"}`,
			"secret": connSecret, "secret_version": "1"}
		if d := p.validate(res, map[string]any{"name": "x", "connector_type": "okta", "secret": "s"}); !strings.Contains(diagText(d), "secret_version") {
			t.Fatalf("a secret without its version: %q", diagText(d))
		}
		st := approveHiding(t, applyAsync(p, res, cfg, tftypes.NewValue(p.resourceType(res), nil)), connSecret).state
		a := attrs(t, st)
		notInState(t, st, connSecret)
		if !uuidRE.MatchString(str(t, a["id"])) || !a["secret"].IsNull() || str(t, a["secret_version"]) != "1" || str(t, a["state"]) == "active" {
			t.Fatalf("created connection: %v", st)
		}
		if again, d := p.read(res, st); len(d) > 0 || !again.Equal(st) {
			t.Fatalf("refresh changed the state: %s\n%v\n%v", diagText(d), st, again)
		}
		// a change of config alone sends no credential; the same version keeps the server's secret
		cfg["config_json"] = `{"org_url":"https://tf2.okta.com"}`
		st2 := approveHiding(t, applyAsync(p, res, cfg, st), connSecret).state
		notInState(t, st2, connSecret)
		// a new version with a new secret rotates it; a new version with no secret is refused before anything is filed
		cfg["secret"], cfg["secret_version"] = "PLAINTEXT-connector-secret-2", "2"
		st3 := approveHiding(t, applyAsync(p, res, cfg, st2), "PLAINTEXT-connector-secret-2").state
		notInState(t, st3, "PLAINTEXT-connector-secret-2")
		if str(t, attrs(t, st3)["secret_version"]) != "2" {
			t.Fatalf("rotated connection: %v", st3)
		}
		delete(cfg, "secret")
		cfg["secret_version"] = "3"
		if _, d := p.apply(res, cfg, st3); !strings.Contains(diagText(d), "Version changed without a secret") {
			t.Fatalf("a new version without a secret: %q", diagText(d))
		}
		// the server's own refusals reach the plan: a metadata host is refused before anyone is asked
		bad := map[string]any{"name": "TF bad", "connector_type": "okta", "config_json": `{"org_url":"https://169.254.169.254"}`}
		if _, d := p.apply(res, bad, tftypes.NewValue(p.resourceType(res), nil)); !strings.Contains(diagText(d), "invalid_config") {
			t.Fatalf("a metadata host: %q", diagText(d))
		}
		imp, d := p.importState(res, str(t, a["id"]))
		if len(d) > 0 {
			t.Fatalf("import: %s", diagText(d))
		}
		if got, d := p.read(res, imp); len(d) > 0 || str(t, attrs(t, got)["name"]) != "TF okta" || str(t, attrs(t, got)["connector_type"]) != "okta" {
			t.Fatalf("read after import: %v %s", got, diagText(d))
		}
	})
	t.Run("alert channel", func(t *testing.T) {
		const res = "tessera_alert_channel"
		cfg := map[string]any{"name": "TF hook", "kind": "webhook", "target": hookURL, "signing_secret": hookSecret, "signing_secret_version": "1"}
		if _, d := p.apply(res, map[string]any{"name": "TF nosecret", "kind": "webhook", "target": hookURL}, tftypes.NewValue(p.resourceType(res), nil)); !strings.Contains(diagText(d), "needs its signing secret") {
			t.Fatalf("a webhook without a secret: %q", diagText(d))
		}
		if _, d := p.apply(res, map[string]any{"name": "TF meta", "kind": "webhook", "target": "https://169.254.169.254/x", "signing_secret": hookSecret,
			"signing_secret_version": "1"}, tftypes.NewValue(p.resourceType(res), nil)); !strings.Contains(diagText(d), "metadata") {
			t.Fatalf("a metadata target: %q", diagText(d))
		}
		st := approveHiding(t, applyAsync(p, res, cfg, tftypes.NewValue(p.resourceType(res), nil)), hookSecret, "PLAINTEXT-url-token").state
		notInState(t, st, hookSecret)
		a := attrs(t, st)
		if !uuidRE.MatchString(str(t, a["id"])) || !a["signing_secret"].IsNull() || str(t, a["min_severity"]) != "high" {
			t.Fatalf("created channel: %v", st)
		}
		cfg["enabled"] = false
		st2 := approveHiding(t, applyAsync(p, res, cfg, st), hookSecret, "PLAINTEXT-url-token").state
		if boolv(t, attrs(t, st2)["enabled"]) || str(t, attrs(t, st2)["id"]) != str(t, a["id"]) {
			t.Fatalf("updated channel: %v", st2)
		}
		// an email channel carries no secret
		mail := map[string]any{"name": "TF mail", "kind": "email", "target": "soc@larkspur.example", "min_severity": "critical"}
		st3 := approveHiding(t, applyAsync(p, res, mail, tftypes.NewValue(p.resourceType(res), nil))).state
		if str(t, attrs(t, st3)["min_severity"]) != "critical" {
			t.Fatalf("email channel: %v", st3)
		}
		if d := p.destroy(res, st2); diagText(d) != "" || len(d) != 1 {
			t.Fatalf("destroy should only warn: %v", d)
		}
	})
	t.Run("siem sink", func(t *testing.T) {
		const res = "tessera_siem_sink"
		cfg := map[string]any{"name": "TF splunk", "kind": "webhook", "flavor": "hec", "target": "https://splunk.example.com:8088/services/collector",
			"token": hecToken, "token_version": "1"}
		if _, d := p.apply(res, map[string]any{"name": "TF notoken", "kind": "webhook", "flavor": "hec", "target": "https://splunk.example.com/x"},
			tftypes.NewValue(p.resourceType(res), nil)); !strings.Contains(diagText(d), "token_required") {
			t.Fatalf("an HEC sink without its token: %q", diagText(d))
		}
		st := approveHiding(t, applyAsync(p, res, cfg, tftypes.NewValue(p.resourceType(res), nil)), hecToken).state
		notInState(t, st, hecToken)
		a := attrs(t, st)
		if !uuidRE.MatchString(str(t, a["id"])) || !a["token"].IsNull() || str(t, a["format"]) != "json" {
			t.Fatalf("created sink: %v", st)
		}
		// the same version keeps the token the server holds; an origin move without a new one is refused by the server
		cfg["include_http"] = true
		st2 := approveHiding(t, applyAsync(p, res, cfg, st), hecToken).state
		if !boolv(t, attrs(t, st2)["include_http"]) {
			t.Fatalf("updated sink: %v", st2)
		}
		cfg["target"] = "https://other.example.com:8088/services/collector"
		if _, d := p.apply(res, cfg, st2); !strings.Contains(diagText(d), "credential_required") {
			t.Fatalf("an origin move without a new token: %q", diagText(d))
		}
		cfg["token"], cfg["token_version"] = "PLAINTEXT-hec-token-2", "2"
		st3 := approveHiding(t, applyAsync(p, res, cfg, st2), "PLAINTEXT-hec-token-2").state
		notInState(t, st3, "PLAINTEXT-hec-token-2")
		imp, d := p.importState(res, str(t, a["id"]))
		if len(d) > 0 {
			t.Fatalf("import: %s", diagText(d))
		}
		if _, d := p.read(res, imp); len(d) > 0 {
			t.Fatalf("read after import: %s", diagText(d))
		}
	})

	// 7. the server refuses a bad proposal before anyone is asked, and says why
	bad := map[string]any{"rule_id": "no_such_rule", "enabled": true, "severity": "high", "threshold": 1, "window_minutes": 5}
	if _, d := p.apply(ruleRes, bad, null); !strings.Contains(diagText(d), "rule_not_found") {
		t.Fatalf("a proposal for an unknown rule: %q", diagText(d))
	}
}
