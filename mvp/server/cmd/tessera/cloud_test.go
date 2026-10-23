package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

// A backup is copied to TESSERA_BACKUP_URL through the guarded client, signed
// with the workload's AWS credentials, as a create-only object.
func TestCopyBackupToObjectStore(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || r.Header.Get("If-None-Match") != "*" {
			http.Error(w, "bad", 400)
			return
		}
		mu.Lock()
		got[r.URL.Path] = b
		mu.Unlock()
	}))
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	dir := t.TempDir()
	env := map[string]string{"TESSERA_ENV": "dev", "TESSERA_OUTBOUND_ALLOW_LOOPBACK": "true", "TESSERA_BACKUP_DIR": dir,
		"TESSERA_BACKUP_URL": "s3://tessera-backups/db?endpoint=" + url.QueryEscape(srv.URL)}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tessera-20261001T120000Z.tbak")
	if err := os.WriteFile(path, []byte("sealed backup bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyBackupToObjectStore(context.Background(), cfg, path); err != nil {
		t.Fatal(err)
	}
	if string(got["/tessera-backups/db/backups/tessera-20261001T120000Z.tbak"]) != "sealed backup bytes" {
		t.Fatalf("uploaded: %v", got)
	}
}
