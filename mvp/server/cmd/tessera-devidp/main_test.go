package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// TestRefusesToStartOutsideDev: the binary exits before doing anything when
// TESSERA_ENV is not dev or test (§18.4), and never binds a non-loopback address.
func TestRefusesToStartOutsideDev(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	for _, tc := range []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{"unset env", nil, nil, "TESSERA_ENV"},
		{"prod", map[string]string{"TESSERA_ENV": "prod"}, nil, "never run in production"},
		{"staging", map[string]string{"TESSERA_ENV": "staging"}, nil, "TESSERA_ENV"},
		{"public bind", map[string]string{"TESSERA_ENV": "dev"}, []string{"-addr", "0.0.0.0:8001", "-key-dir", keyDir}, "loopback only"},
		{"lan bind", map[string]string{"TESSERA_ENV": "dev"}, []string{"-addr", "192.168.1.5:8001", "-key-dir", keyDir}, "loopback only"},
		{"bad profile", map[string]string{"TESSERA_ENV": "dev"}, []string{"-addr", "127.0.0.1:0", "-key-dir", keyDir, "-profile", "keycloak"}, "unknown profile"},
		{"stray args", map[string]string{"TESSERA_ENV": "test"}, []string{"serve"}, "unexpected arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(context.Background(), tc.args, env(tc.env), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run: %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

func TestCheckLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:8001": true, "[::1]:8001": true, "localhost:8001": true,
		":8001": false, "0.0.0.0:8001": false, "10.0.0.1:8001": false, "example.com:8001": false} {
		if err := checkLoopback(addr); (err == nil) != ok {
			t.Errorf("checkLoopback(%q) = %v", addr, err)
		}
	}
}
