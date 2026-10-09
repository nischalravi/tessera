package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
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
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_CORS_ORIGINS", "")
	db := filepath.Join(t.TempDir(), "t.db")
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	var out, logs bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"serve", "-addr", addr, "-db", db}, &out, &logs) }()

	var resp *http.Response
	var err error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if resp, err = http.Get(fmt.Sprintf("http://%s/api/health", addr)); err == nil {
			break
		}
	}
	if err != nil {
		cancel()
		t.Fatalf("server did not come up: %v\n%s", err, logs.String())
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("health: %d %v", resp.StatusCode, resp.Header)
	}
	if !strings.Contains(out.String(), "Seeded Tessera") {
		t.Errorf("missing seed output: %q", out.String())
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
	if !strings.Contains(logs.String(), "shutting down") {
		t.Errorf("logs: %s", logs.String())
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
