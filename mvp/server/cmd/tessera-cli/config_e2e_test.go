package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/transport"
)

// config export, plan and apply against an in-process API (issue #497): the
// real router and authorization server, so the bundle is signed, verified and
// applied as for the UI, and the apply needs the same fresh sign-in.
func TestConfigCLI_ExportPlanApply(t *testing.T) {
	w := newWorld(t)
	// the default scopes cannot reach the transport routes: the CLI says which scope to ask for
	if r := w.login("alice@tiny.example", tenantAdmin, "approve"); r.code != 0 {
		t.Fatalf("login: %s %s", r.stdout, r.stderr)
	}
	if r := w.run("config", "key"); r.code != exitError || !strings.Contains(r.stderr, "tessera:admin") {
		t.Errorf("config key without the admin scope: exit %d %s", r.code, r.stderr)
	}
	if r := w.login("alice@tiny.example", tenantAdmin, "approve", "--scope", "tessera:admin"); r.code != 0 {
		t.Fatalf("login: %s %s", r.stdout, r.stderr)
	}
	// something the version 2 bundle carries: an alert rule setting
	if err := w.db.InTenant(context.Background(), w.tenant, func(tx *store.TenantTx) error {
		return tx.PutAlertRuleSetting(&store.AlertRuleSetting{RuleID: "mfa_bypass", Enabled: true, Severity: "critical", Threshold: 1,
			WindowMinutes: 30, UpdatedAt: w.clock.Now()})
	}); err != nil {
		t.Fatal(err)
	}

	r := w.ok("config", "key")
	if !strings.Contains(r.stdout, "No signing key yet") {
		t.Errorf("key before the first export: %s", r.stdout)
	}
	file := filepath.Join(t.TempDir(), "bundle.json")
	r = w.ok("config", "export", "-o", file)
	if !strings.Contains(r.stderr, "exported, hash ") {
		t.Errorf("export: %s", r.stderr)
	}
	raw, err := os.ReadFile(file)
	if err != nil || !json.Valid(raw) || !strings.Contains(string(raw), `"protected"`) {
		t.Fatalf("bundle file: %v %s", err, raw)
	}
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o600 {
		t.Errorf("bundle mode %v", info.Mode().Perm())
	}
	r = w.ok("config", "key")
	if !strings.Contains(r.stdout, "kid ") || !strings.Contains(r.stdout, "public_key ") {
		t.Errorf("key: %s", r.stdout)
	}

	// untrusted: the destination refuses a bundle from a signer it does not list
	if r := w.run("config", "plan", "-f", file); r.code != exitError || !strings.Contains(r.stderr, "untrusted_signer") {
		t.Errorf("plan of an untrusted bundle: exit %d %s %s", r.code, r.stdout, r.stderr)
	}
	// trust the tenant's own key (the pipeline's destination would add the source's)
	if err := w.db.InTenant(context.Background(), w.tenant, func(tx *store.TenantTx) error {
		k, err := tx.ActiveConfigSigningKey()
		if err != nil {
			return err
		}
		return tx.InsertTrustedSigner(&store.TrustedSigner{KID: k.KID, PublicKey: k.PublicKey, Label: "self", AddedAt: w.clock.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	r = w.ok("config", "plan", "-f", file)
	if !strings.Contains(r.stdout, "add 0") || !strings.Contains(r.stdout, "signed by self") {
		t.Errorf("plan: %s", r.stdout)
	}
	// the destination differs: change the alert rule here, then the plan wants to put it back
	if err := w.db.InTenant(context.Background(), w.tenant, func(tx *store.TenantTx) error {
		return tx.PutAlertRuleSetting(&store.AlertRuleSetting{RuleID: "mfa_bypass", Enabled: false, Severity: "low", Threshold: 9,
			WindowMinutes: 30, UpdatedAt: w.clock.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	r = w.ok("config", "plan", "-f", file, "--json")
	var p struct {
		Digest string `json:"digest"`
		Items  []struct{ Section, Name, Action string }
	}
	if err := json.Unmarshal([]byte(r.stdout), &p); err != nil || p.Digest == "" {
		t.Fatalf("plan --json: %v %s", err, r.stdout)
	}
	changed := false
	for _, it := range p.Items {
		changed = changed || (it.Section == transport.SecAlertRules && it.Name == "mfa_bypass" && it.Action == transport.Change)
	}
	if !changed {
		t.Errorf("plan items %+v", p.Items)
	}
	// a stale digest is refused before anything is sent
	before := len(w.events("config.import.applied"))
	if r := w.run("config", "apply", "-f", file, "--digest", "deadbeef"); r.code != exitError || !strings.Contains(r.stderr, "not the one you reviewed") {
		t.Errorf("apply with a wrong digest: exit %d %s", r.code, r.stderr)
	}
	if len(w.events("config.import.applied")) != before {
		t.Error("a refused apply was audited as applied")
	}
	r = w.ok("config", "apply", "-f", file, "--digest", p.Digest)
	if !strings.Contains(r.stdout, "applied (import ") {
		t.Errorf("apply: %s", r.stdout)
	}
	if len(w.events("config.import.applied")) != before+1 {
		t.Error("the apply was not audited")
	}
	var got []*store.AlertRuleSetting
	_ = w.db.ReadTenant(context.Background(), w.tenant, func(tx *store.TenantTx) (err error) {
		got, err = tx.AlertRuleSettings()
		return err
	})
	if len(got) != 1 || !got[0].Enabled || got[0].Severity != "critical" {
		t.Errorf("the rule was not restored: %+v", got)
	}
	// usage errors are exit 2
	if r := w.run("config", "plan"); r.code != exitUsage {
		t.Errorf("plan without -f: %d", r.code)
	}
	if r := w.run("config", "plan", "-f", file, "--prune"); r.code != exitUsage {
		t.Errorf("plan --prune: %d", r.code)
	}
	if r := w.run("config", "nope"); r.code != exitUsage {
		t.Errorf("unknown: %d", r.code)
	}
	if r := w.run("config", "plan", "-f", filepath.Join(t.TempDir(), "missing.json")); r.code != exitUsage {
		t.Errorf("missing file: %d", r.code)
	}
}
