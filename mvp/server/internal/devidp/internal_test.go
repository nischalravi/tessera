package devidp

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMatchRedirect(t *testing.T) {
	for _, tc := range []struct {
		pattern, uri string
		want         bool
	}{
		{"http://127.0.0.1:8000/cb", "http://127.0.0.1:8000/cb", true},
		{"http://127.0.0.1:8000/cb", "http://127.0.0.1:8000/cb/", false},
		{"http://127.0.0.1:8000/cb", "http://127.0.0.1:8000/cb?x=1", false},
		{"http://127.0.0.1:*/cb", "http://127.0.0.1:5173/cb", true},
		{"http://127.0.0.1:*/cb", "http://127.0.0.1:/cb", false},
		{"http://127.0.0.1:*/cb", "http://127.0.0.1:1@evil.example/cb", false}, // a wildcard never matches userinfo
		{"http://127.0.0.1:*/cb", "http://127.0.0.1:1/x/cb", false},
		{"http://localhost:*/api/auth/oidc/*/callback", "http://localhost:5173/api/auth/oidc/1f0c-uuid/callback", true},
		{"http://localhost:*/api/auth/oidc/*/callback", "http://localhost:5173/api/auth/oidc/a/b/callback", false},
		{"http://localhost:*/api/auth/oidc/*/callback", "http://localhost:5173/api/auth/oidc/a/callback#frag", false},
		{"http://localhost:*/api/auth/oidc/*/callback", "http://localhost.evil.example/api/auth/oidc/a/callback", false},
		{"http://localhost:*/api/auth/oidc/*/callback", "http://localhost:5173/api/auth/oidc/a?/callback", false},
		{"http://localhost:*/api/auth/oidc/*/callback", "http://localhost:5173/api/auth/oidc/../callback", false},
		{"http://localhost:*/api/auth/oidc/*/callback", "http://localhost:5173/api/auth/oidc/./callback", false},
		{"http://localhost:*/api/auth/oidc/*/callback", "http://localhost:5173/api/auth/oidc/.../callback", true},
		{"http://localhost:*/api/auth/oidc/*/callback", "http://localhost:5173/api/auth/oidc/v1.2/callback", true},
	} {
		if got := matchRedirect(tc.pattern, tc.uri); got != tc.want {
			t.Errorf("matchRedirect(%q, %q) = %v, want %v", tc.pattern, tc.uri, got, tc.want)
		}
	}
}

func TestParseUsers(t *testing.T) {
	users, err := DefaultUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 6 || users[0].Sub != "00u-alice-admin" || !users[0].has(MethodPasskey) {
		t.Fatalf("embedded users: %+v", users)
	}
	for _, tc := range []struct{ name, yaml, err string }{
		{"empty", "", "empty"},
		{"no users", "[]", "no users"},
		{"unknown field", `- {sub: a, email: a@x, name: A, tenant: t, authenticators: [password], admin: true}`, "admin"},
		{"duplicate", "- {sub: a, email: a@x, name: A, tenant: t, authenticators: [password]}\n- {sub: a, email: b@x, name: B, tenant: t, authenticators: [password]}", "duplicate"},
		{"unknown method", `- {sub: a, email: a@x, name: A, tenant: t, authenticators: [sms]}`, "unknown authenticator"},
		{"no method", `- {sub: a, email: a@x, name: A, tenant: t}`, "authenticator"},
		{"no tenant", `- {sub: a, email: a@x, name: A, authenticators: [password]}`, "tenant"},
		{"too big", strings.Repeat("#", maxUsersFile+1), "larger"},
	} {
		if _, err := ParseUsers([]byte(tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s: err %v, want it to mention %q", tc.name, err, tc.err)
		}
	}
}

func TestProductionGuards(t *testing.T) {
	for env, ok := range map[string]bool{"dev": true, "test": true, "": false, "prod": false, "production": false, "Dev": false, "staging": false} {
		if err := CheckEnv(env); (err == nil) != ok {
			t.Errorf("CheckEnv(%q) = %v", env, err)
		}
	}
	t.Setenv("TESSERA_ENV", "prod")
	if _, err := New(Config{Issuer: "http://127.0.0.1:8001"}); err == nil {
		t.Fatal("New succeeded with TESSERA_ENV=prod")
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	for _, cfg := range []Config{
		{Issuer: ""},
		{Issuer: "ftp://x"},
		{Issuer: "http://127.0.0.1:8001/"},
		{Issuer: "http://127.0.0.1:8001?x=1"},
		{Issuer: "http://127.0.0.1:8001", DefaultProfile: "keycloak"},
		{Issuer: "http://127.0.0.1:8001", Clients: []Client{{ID: "c", RedirectURIs: []string{"http://x/cb"}}}},
		{Issuer: "http://127.0.0.1:8001", Clients: []Client{{ID: "c", Secret: "s", RedirectURIs: []string{"http://x/cb"}}, {ID: "c", Secret: "s", RedirectURIs: []string{"http://x/cb"}}}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "devidp")
	k1, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v, want 0600", st.Mode().Perm())
	}
	k2, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Equal(k2) {
		t.Error("the stored key was not reloaded")
	}
	if err := os.Chmod(filepath.Join(dir, KeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(dir); err == nil || !strings.Contains(err.Error(), "other users") {
		t.Errorf("world-readable key accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(dir); err == nil {
		t.Error("junk key accepted")
	}
}

func TestTTLStoreBound(t *testing.T) {
	var st ttlStore[int]
	now := time.Now()
	for i := range maxEntries {
		if err := st.put(strconv.Itoa(i), i, now.Add(time.Minute), now); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if err := st.put("one-more", 0, now.Add(time.Minute), now); !errors.Is(err, errStoreFull) {
		t.Fatalf("put past the bound: %v", err)
	}
	// Once entries expire, the store sweeps them and accepts again.
	later := now.Add(time.Minute)
	if err := st.put("after-expiry", 1, later.Add(time.Minute), later); err != nil {
		t.Fatalf("put after expiry: %v", err)
	}
	if fresh, _ := st.putNew("after-expiry", 2, later.Add(time.Minute), later); fresh {
		t.Error("putNew overwrote a live entry")
	}
	if _, ok := st.take("after-expiry", later); !ok {
		t.Error("take lost the entry")
	}
	if _, ok := st.take("after-expiry", later); ok {
		t.Error("take returned an entry twice")
	}
}
