package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Acceptance tests against a real `tessera serve` (see testserver_test.go). Set TF_ACC=1 to run them.
// They drive the provider through the plugin protocol, in process: configure, plan, apply, read, import, destroy.

const scheduleRes = "tessera_review_schedule"

func (ts *testServer) providerConfig(clientID string, dpop bool) map[string]any {
	return map[string]any{"endpoint": ts.URL, "tenant": ts.Tenant, "client_id": clientID, "private_key_file": ts.KeyFile,
		"key_id": ts.KeyID, "dpop": dpop}
}

func TestAcc_ReviewSchedule_Lifecycle(t *testing.T) {
	ts := startTestServer(t)
	// the DPoP-bound client: a Bearer token would be refused for it, so this covers the proof on every call
	p := newProtocol(t)
	if d := p.configure(ts.providerConfig(ts.DPoPID, true)); len(d) > 0 {
		t.Fatalf("configure: %s", diagText(d))
	}

	cfg := map[string]any{"name": "tf quarterly review", "recurrence": "quarterly", "first_run_at": "2027-01-01T00:00:00Z",
		"privileged_only": true, "unused_days": 45, "reminder_days": 2}
	null := tftypes.NewValue(p.resourceType(scheduleRes), nil)

	// create
	st, d := p.apply(scheduleRes, cfg, null)
	if len(d) > 0 {
		t.Fatalf("create: %s", diagText(d))
	}
	a := attrs(t, st)
	id := str(t, a["id"])
	if !uuidRE.MatchString(id) {
		t.Fatalf("id %q is not a UUID", id)
	}
	if got := str(t, a["next_run_at"]); !strings.HasPrefix(got, "2027-01-01T00:00:00") {
		t.Fatalf("next_run_at = %s", got)
	}
	for k, want := range map[string]int64{"unused_days": 45, "duration_days": 14, "reminder_days": 2, "escalation_days": 7} {
		if got := num(t, a[k]); got != want {
			t.Fatalf("%s = %d, want %d", k, got, want)
		}
	}
	if str(t, a["close_out"]) != "revoke" || !a["enabled"].Equal(tftypes.NewValue(tftypes.Bool, true)) {
		t.Fatalf("defaults not applied: close_out=%s", str(t, a["close_out"]))
	}

	// refresh is a no-op: nothing the plan did not produce
	again, d := p.read(scheduleRes, st)
	if len(d) > 0 {
		t.Fatalf("read: %s", diagText(d))
	}
	if !again.Equal(st) {
		t.Fatalf("refresh changed the state:\n%v\n%v", st, again)
	}

	// update in place: a new name and window; first_run_at unchanged so the server keeps the next run
	cfg["name"], cfg["duration_days"] = "tf quarterly review (renamed)", 21
	st2, d := p.apply(scheduleRes, cfg, st)
	if len(d) > 0 {
		t.Fatalf("update: %s", diagText(d))
	}
	a2 := attrs(t, st2)
	if str(t, a2["id"]) != id || str(t, a2["name"]) != "tf quarterly review (renamed)" || num(t, a2["duration_days"]) != 21 {
		t.Fatalf("update not applied: %v", st2)
	}
	if str(t, a2["next_run_at"]) != str(t, a["next_run_at"]) {
		t.Fatalf("next_run_at moved on an update that did not change first_run_at: %s -> %s", str(t, a["next_run_at"]), str(t, a2["next_run_at"]))
	}

	// the server's validation reaches the user (a system that does not exist)
	bad := map[string]any{"name": "tf bad", "recurrence": "annual", "first_run_at": "2027-01-01T00:00:00Z", "system": "no-such-system"}
	if _, d := p.apply(scheduleRes, bad, null); !strings.Contains(diagText(d), "invalid_system") {
		t.Fatalf("want invalid_system, got %q", diagText(d))
	}

	// import by id gives the same state, except first_run_at (configuration, not read back)
	imp, d := p.importState(scheduleRes, id)
	if len(d) > 0 {
		t.Fatalf("import: %s", diagText(d))
	}
	imp, d = p.read(scheduleRes, imp)
	if len(d) > 0 {
		t.Fatalf("read after import: %s", diagText(d))
	}
	ia, want := attrs(t, imp), attrs(t, st2)
	for k, v := range want {
		if k == "first_run_at" {
			continue
		}
		if !ia[k].Equal(v) {
			t.Errorf("imported %s = %v, want %v", k, ia[k], v)
		}
	}
	if !ia["first_run_at"].IsNull() {
		t.Errorf("first_run_at should be null after an import")
	}

	// destroy disables the schedule (the API has no delete route); the resource is gone from state, and a re-read of the
	// old state finds the schedule still there, disabled
	if d := p.destroy(scheduleRes, st2); len(d) > 0 {
		t.Fatalf("destroy: %s", diagText(d))
	}
	disabled, d := p.read(scheduleRes, st2)
	if len(d) > 0 {
		t.Fatalf("read after destroy: %s", diagText(d))
	}
	if !attrs(t, disabled)["enabled"].Equal(tftypes.NewValue(tftypes.Bool, false)) {
		t.Fatalf("destroy did not disable the schedule: %v", disabled)
	}

	// a schedule that is not there any more drops out of state
	gone := attrs(t, st2)
	gone["id"] = tftypes.NewValue(tftypes.String, "00000000-0000-4000-8000-000000000000")
	gst, d := p.read(scheduleRes, tftypes.NewValue(p.resourceType(scheduleRes), gone))
	if len(d) > 0 {
		t.Fatalf("read of a missing schedule: %s", diagText(d))
	}
	if !gst.IsNull() {
		t.Fatalf("a missing schedule must leave the state, got %v", gst)
	}
}

func TestAcc_ReviewSchedule_DisabledNeedsNoFirstRun(t *testing.T) {
	ts := startTestServer(t)
	p := newProtocol(t)
	if d := p.configure(ts.providerConfig(ts.BearerID, false)); len(d) > 0 {
		t.Fatalf("configure: %s", diagText(d))
	}
	null := tftypes.NewValue(p.resourceType(scheduleRes), nil)
	// enabled without a first run is the server's refusal
	if _, d := p.apply(scheduleRes, map[string]any{"name": "tf x", "recurrence": "once"}, null); !strings.Contains(diagText(d), "first_run_required") {
		t.Fatalf("want first_run_required, got %q", diagText(d))
	}
	st, d := p.apply(scheduleRes, map[string]any{"name": "tf x", "recurrence": "once", "enabled": false}, null)
	if len(d) > 0 {
		t.Fatalf("create: %s", diagText(d))
	}
	if !attrs(t, st)["enabled"].Equal(tftypes.NewValue(tftypes.Bool, false)) {
		t.Fatalf("enabled = %v", attrs(t, st)["enabled"])
	}
	if d := p.destroy(scheduleRes, st); len(d) > 0 {
		t.Fatalf("destroy: %s", diagText(d))
	}
}

func TestAcc_Auth_Refusals(t *testing.T) {
	ts := startTestServer(t)
	null := func(p *protocol) tftypes.Value { return tftypes.NewValue(p.resourceType(scheduleRes), nil) }
	cfg := map[string]any{"name": "tf x", "recurrence": "once", "enabled": false}

	t.Run("a Bearer request for a DPoP-bound client is refused", func(t *testing.T) {
		p := newProtocol(t)
		if d := p.configure(ts.providerConfig(ts.DPoPID, false)); len(d) > 0 {
			t.Fatalf("configure does no I/O: %s", diagText(d))
		}
		if _, d := p.apply(scheduleRes, cfg, null(p)); len(d) == 0 {
			t.Fatal("the server issued a token without a DPoP proof to a dpop_required client")
		}
	})
	t.Run("a wrong tenant", func(t *testing.T) {
		p := newProtocol(t)
		c := ts.providerConfig(ts.BearerID, false)
		c["tenant"] = "nosuchtenant"
		p.configure(c)
		if _, d := p.apply(scheduleRes, cfg, null(p)); !strings.Contains(diagText(d), "tenant") {
			t.Fatalf("got %q", diagText(d))
		}
	})
	t.Run("an unknown client", func(t *testing.T) {
		p := newProtocol(t)
		p.configure(ts.providerConfig("tsc_doesnotexist", false))
		if _, d := p.apply(scheduleRes, cfg, null(p)); len(d) == 0 {
			t.Fatal("an unregistered client got a token")
		}
	})
	t.Run("a key the client has not registered", func(t *testing.T) {
		p := newProtocol(t)
		_, other := testKeyPEM(t)
		c := ts.providerConfig(ts.BearerID, false)
		delete(c, "private_key_file")
		c["private_key"] = other
		p.configure(c)
		_, d := p.apply(scheduleRes, cfg, null(p))
		if !strings.Contains(diagText(d), "invalid_client") {
			t.Fatalf("got %q", diagText(d))
		}
	})
}

func TestAcc_DataSources(t *testing.T) {
	ts := startTestServer(t)
	p := newProtocol(t)
	if d := p.configure(ts.providerConfig(ts.BearerID, false)); len(d) > 0 {
		t.Fatalf("configure: %s", diagText(d))
	}
	list := func(t *testing.T, name string, filter map[string]any, key string) []tftypes.Value {
		t.Helper()
		m, d := p.readData(name, filter)
		if len(d) > 0 {
			t.Fatalf("%s: %s", name, diagText(d))
		}
		var l []tftypes.Value
		if err := m[key].As(&l); err != nil {
			t.Fatal(err)
		}
		return l
	}

	ids := list(t, "tessera_identities", map[string]any{"query": "ingrid"}, "identities")
	if len(ids) != 1 || str(t, attrs(t, ids[0])["email"]) != "ingrid.lindqvist@larkspur.example" {
		t.Fatalf("identities?q=ingrid = %v", ids)
	}
	if all := list(t, "tessera_identities", nil, "identities"); len(all) < 10 {
		t.Fatalf("only %d identities", len(all))
	}
	if none := list(t, "tessera_identities", map[string]any{"query": "zzz-nobody"}, "identities"); len(none) != 0 {
		t.Fatalf("a query with no match returned %d", len(none))
	}

	aws := list(t, "tessera_entitlements", map[string]any{"system": "aws"}, "entitlements")
	if len(aws) == 0 {
		t.Fatal("no aws entitlements")
	}
	for _, e := range aws {
		if str(t, attrs(t, e)["system"]) != "aws" {
			t.Fatalf("filter leaked %v", e)
		}
	}
	if all := list(t, "tessera_entitlements", nil, "entitlements"); len(all) <= len(aws) {
		t.Fatalf("the system filter did not narrow: %d vs %d", len(all), len(aws))
	}

	conns := list(t, "tessera_connectors", nil, "connectors")
	if len(conns) == 0 {
		t.Fatal("no connectors")
	}
	okta := list(t, "tessera_connectors", map[string]any{"system": "okta"}, "connectors")
	if len(okta) == 0 || len(okta) >= len(conns) {
		t.Fatalf("okta connectors = %d of %d", len(okta), len(conns))
	}
}
