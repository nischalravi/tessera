package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestServeSeedsAndShutsDownGracefully(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_CORS_ORIGINS", "")
	db := filepath.Join(t.TempDir(), "t.db")
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	var out, logs bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"serve", "-addr", addr, "-db", db}, &out, &logs) }()

	// Seeding runs first; under -race on a loaded CI runner it can take a while.
	var resp *http.Response
	var err error
	for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		select {
		case runErr := <-done:
			cancel()
			t.Fatalf("run exited before serving: %v", runErr)
		default:
		}
		if resp, err = http.Get(fmt.Sprintf("http://%s/api/health", addr)); err == nil {
			break
		}
	}
	if err != nil {
		cancel()
		t.Fatalf("server did not come up: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("health: %d %v", resp.StatusCode, resp.Header)
	}
	if !strings.Contains(out.String(), "Seeded Tessera") || !strings.Contains(out.String(), "deployment-readiness demo") ||
		!strings.Contains(out.String(), "signing keys") {
		t.Errorf("missing seed output: %q", out.String())
	}
	// the dev KEK was generated next to the database, readable only by its owner
	if fi, err := os.Stat(filepath.Join(filepath.Dir(db), "var", "dev-kek")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("dev KEK: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
	if !strings.Contains(logs.String(), "shutting down") { // read only after run returned
		t.Errorf("logs: %s", logs.String())
	}
}

// TestServeRefusesWithoutExplicitEnv: the environment decides the guard
// rails and whether dev sign-in exists, so it must be explicit; and
// production never seeds the demo tenants (a fresh production database is
// created with the admin CLI, §15.3).
func TestServeRefusesWithoutExplicitEnv(t *testing.T) {
	for env, want := range map[string]string{
		"":     "set TESSERA_ENV=dev",
		"DEV":  "TESSERA_ENV=dev",
		"prod": "refusing to seed demo tenants with TESSERA_ENV=prod",
	} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("TESSERA_ENV", env)
			t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
			if env == "prod" { // a production configuration that passes every guard rail
				prodEnv(t)
			}
			db := filepath.Join(t.TempDir(), "t.db")
			var out, logs bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			err := run(ctx, []string{"serve", "-addr", freePort(t), "-db", db}, &out, &logs)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("serve with TESSERA_ENV=%q: %v, want a refusal naming %q", env, err, want)
			}
		})
	}
}

// prodEnv sets a production configuration that passes every guard rail.
func prodEnv(t *testing.T) {
	t.Setenv("TESSERA_ENV", "prod")
	t.Setenv("TESSERA_NOW", "")
	t.Setenv("TESSERA_PUBLIC_URL", "https://tessera.example.com")
	t.Setenv("TESSERA_KEK", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	t.Setenv("TESSERA_CORS_ORIGINS", "")
	t.Setenv("TESSERA_AUDIT_ANCHOR", "s3://anchors/tessera")
	t.Setenv("TESSERA_DEV_IDP_URL", "")
}

// TestProdRefusesDevMockConnection: a database seeded in dev has dev_mock
// IdP connections (the dev sign-in users); production refuses to serve it
// (§18.4).
func TestProdRefusesDevMockConnection(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_READINESS_DEMO", "off")
	db := filepath.Join(t.TempDir(), "t.db")
	var out, logs bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := run(ctx, []string{"seed", "-db", db}, &out, &logs); err != nil {
		t.Fatal(err)
	}
	prodEnv(t)
	err := run(ctx, []string{"serve", "-addr", freePort(t), "-db", db}, &out, &logs)
	if err == nil || !strings.Contains(err.Error(), "dev_mock IdP connection") {
		t.Errorf("prod serve over a dev database: %v, want a dev_mock refusal", err)
	}
}

// TestProdGuardRailsRefuseBeforeAnythingRuns: with TESSERA_ENV=prod and an
// unsafe setting, serve and seed refuse before touching the database.
func TestProdGuardRailsRefuseBeforeAnythingRuns(t *testing.T) {
	t.Setenv("TESSERA_ENV", "prod")
	t.Setenv("TESSERA_PUBLIC_URL", "http://tessera.example.com")
	t.Setenv("TESSERA_CORS_ORIGINS", "*")
	for _, cmd := range []string{"serve", "seed"} {
		t.Run(cmd, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "t.db")
			var out, logs bytes.Buffer
			args := []string{cmd, "-db", db}
			if cmd == "serve" {
				args = append(args, "-addr", freePort(t))
			}
			err := run(context.Background(), args, &out, &logs)
			if err == nil || !strings.Contains(err.Error(), "refusing to start with TESSERA_ENV=prod") ||
				!strings.Contains(err.Error(), "TESSERA_CORS_ORIGINS must be empty") || !strings.Contains(err.Error(), "must be https") {
				t.Errorf("%s: %v", cmd, err)
			}
			if _, err := os.Stat(db); err == nil {
				t.Errorf("%s created the database before refusing", cmd)
			}
		})
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run(context.Background(), []string{"frobnicate"}, &out, &errb); err == nil {
		t.Error("want error")
	}
}

func TestDBPath(t *testing.T) {
	for in, want := range map[string]string{"": "tessera.db", "sqlite:////tmp/x.db": "/tmp/x.db", "y.db": "y.db"} {
		if got := dbPath(in); got != want {
			t.Errorf("dbPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadinessLint(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run(context.Background(), []string{"readiness", "lint"}, &out, &errb); err != nil {
		t.Fatalf("lint: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "templates OK") || !strings.Contains(out.String(), "ad ") {
		t.Errorf("output: %s", out.String())
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "base.yaml")
	if err := os.WriteFile(bad, []byte("template: base\nversion: x\ndisplay_name: B\nconnector_types: []\nitems: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(context.Background(), []string{"readiness", "lint", "-dir", dir}, &out, &errb); err == nil {
		t.Errorf("bad template accepted: %s", out.String())
	}
	if err := run(context.Background(), []string{"readiness"}, &out, &errb); err == nil {
		t.Error("missing subcommand accepted")
	}
}
