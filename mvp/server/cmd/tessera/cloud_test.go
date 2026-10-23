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

func TestWrapKEKCmd_Validation(t *testing.T) {
	var out, errb strings.Builder
	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{"no kms", nil, "", "-kms"},
		{"bad kms", []string{"-kms", "vault:x"}, "", "unknown KMS provider"},
		{"bad stdin", []string{"-kms", "gcp:projects/p/locations/g/keyRings/r/cryptoKeys/k"}, "not a key", "stdin must hold a KEK"},
		{"short key", []string{"-kms", "gcp:projects/p/locations/g/keyRings/r/cryptoKeys/k"}, "AAAA", "stdin must hold a KEK"},
	} {
		err := wrapKEKCmd(context.Background(), tc.args, strings.NewReader(tc.stdin), &out, &errb)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	if out.Len() != 0 {
		t.Errorf("printed something on failure: %q", out.String())
	}
}

// A wrapped KEK is never replaced by a generated dev KEK when the unwrap fails.
func TestLoadSealer_WrappedFailsClosed(t *testing.T) {
	env := map[string]string{"TESSERA_ENV": "dev", "TESSERA_KEK_WRAPPED": "AQIDBAUGBwgJCgsMDQ4PEA==",
		"TESSERA_KEK_KMS": "gcp:projects/p/locations/g/keyRings/r/cryptoKeys/k"}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dev := filepath.Join(t.TempDir(), "var", "dev-kek")
	if _, err := loadSealer(ctx, cfg, dev); err == nil {
		t.Fatal("expected the unwrap to fail")
	}
	if _, err := os.Stat(dev); err == nil {
		t.Fatal("a dev KEK was generated after a failed unwrap")
	}
}
