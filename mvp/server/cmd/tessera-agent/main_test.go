package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
)

func writeConfig(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	dir := t.TempDir()
	cfg := map[string]any{"server_url": "https://tessera.example:8443", "server_ca_file": filepath.Join(dir, "ca.pem"),
		"state_dir": filepath.Join(dir, "state"), "allowed_targets": []string{"ldap.corp.example:636"}}
	if mutate != nil {
		mutate(cfg)
	}
	raw, _ := json.Marshal(cfg)
	p := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func do(args []string, stdin string) (string, error) {
	var out, errOut bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out, &errOut)
	return out.String(), err
}

func TestVersionAndUsage(t *testing.T) {
	out, err := do([]string{"version"}, "")
	if err != nil || !strings.Contains(out, agent.Version) {
		t.Errorf("version: %q %v", out, err)
	}
	for _, args := range [][]string{nil, {"bogus", "-config", "/nonexistent"}, {"run", "-config", "/nonexistent"}} {
		if _, err := do(args, ""); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

// TestCredentialCommands: the secret comes from stdin, never an argument; the
// store lists names only; a bad name is refused.
func TestCredentialCommands(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX permissions")
	}
	cfg := writeConfig(t, nil)
	out, err := do([]string{"credential", "-config", cfg, "set", "svc-ldap"}, "hunter2-secret\n")
	if err != nil || strings.Contains(out, "hunter2-secret") {
		t.Fatalf("set: %q %v", out, err)
	}
	if out, err = do([]string{"credential", "-config", cfg, "list"}, ""); err != nil || strings.TrimSpace(out) != "svc-ldap" {
		t.Errorf("list: %q %v", out, err)
	}
	c, _ := agent.LoadConfig(cfg)
	st, err := agent.NewPlatformStore(filepath.Join(c.StateDir, "credentials"))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := st.Get("svc-ldap"); err != nil || v != "hunter2-secret" {
		t.Errorf("stored: %q %v", v, err)
	}
	for _, args := range [][]string{{"credential", "-config", cfg, "set", "../x"}, {"credential", "-config", cfg, "set"},
		{"credential", "-config", cfg, "frobnicate"}, {"credential", "-config", cfg}} {
		if _, err := do(args, "x\n"); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	if _, err := do([]string{"credential", "-config", cfg, "set", "empty"}, "\n"); err == nil {
		t.Error("an empty secret was stored")
	}
	if _, err := do([]string{"credential", "-config", cfg, "delete", "svc-ldap"}, ""); err != nil {
		t.Error(err)
	}
	if _, err := st.Get("svc-ldap"); err == nil {
		t.Error("deleted credential still readable")
	}
}

// TestConfigRefused: a configuration another user can write is refused, as is
// one with a bad allowlist.
func TestConfigRefused(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX permissions")
	}
	loose := writeConfig(t, nil)
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := do([]string{"credential", "-config", loose, "list"}, ""); err == nil {
		t.Error("a world-writable configuration was used")
	}
	bad := writeConfig(t, func(m map[string]any) { m["allowed_targets"] = []string{"*:636"} })
	if _, err := do([]string{"credential", "-config", bad, "list"}, ""); err == nil {
		t.Error("a wildcard allowlist was used")
	}
}

func TestLDAPProberFactoryIsReadOnlyProber(t *testing.T) {
	// the factory is the only place the agent builds a directory client; it
	// returns the read-only Prober (a compile-time property, pinned here)
	var _ agent.ProberFactory = ldapProber
}

// TestExecutor_CarriesTheModules: the agent registers the RACF and IBM i
// modules next to the built-in LDAP reader (the plug-in host, issue #561), and
// the IBM i module answers "unsupported" in this build.
func TestExecutor_CarriesTheModules(t *testing.T) {
	cfg, err := agent.LoadConfig(writeConfig(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	ex, err := executor(cfg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ex.ModuleList(), ","); got != "ibmi,racf" {
		t.Errorf("modules = %s", got)
	}
	if ex.NewSyncer == nil || ex.New == nil {
		t.Error("the built-in LDAP reader is missing")
	}
	sy, err := ex.Modules[agent.ModuleIBMi](agent.ProberSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sy.Discover(t.Context(), agent.SyncLimits{Accounts: 1, Groups: 1, Members: 1}); !errors.Is(err, connectors.ErrUnsupported) {
		t.Errorf("ibmi: %v", err)
	}
}
