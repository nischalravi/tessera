package cliauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sample(t *testing.T) *Credentials {
	t.Helper()
	_, jwk, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return &Credentials{Server: "https://tessera.example", Tenant: "acme", Issuer: "https://tessera.example/t/acme",
		ClientID: ClientID, Scope: DefaultScope, DPoPKey: jwk, RefreshToken: "trt_abc", SignedInAt: time.Now()}
}

func TestStoreRoundTripAndModes(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "cfg", "tessera")}
	if _, err := s.Load(); err != ErrNotLoggedIn {
		t.Fatalf("empty store: %v", err)
	}
	c := sample(t)
	if err := s.Save(c); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(s.Path()); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("file: %v %v", st, err)
	}
	if st, err := os.Stat(s.Dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("directory: %v %v", st, err)
	}
	got, err := s.Load()
	if err != nil || got.RefreshToken != "trt_abc" || got.Version != CredentialsVersion {
		t.Fatalf("load: %+v %v", got, err)
	}
	if k, err := got.Key(); err != nil || k == nil {
		t.Errorf("key: %v", err)
	}
	// a rewrite leaves no temporary file behind and keeps the mode
	c.RefreshToken = "trt_def"
	if err := s.Save(c); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(s.Dir)
	if len(ents) != 1 || ents[0].Name() != "credentials.json" {
		t.Errorf("directory holds %v", ents)
	}
	// group- or world-accessible files are refused, whatever the bits
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o666, 0o601} {
		if err := os.Chmod(s.Path(), mode); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %04o accepted: %v", mode, err)
		}
	}
	if err := os.Chmod(s.Path(), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err != nil {
		t.Errorf("a read-only owner file: %v", err)
	}
	if err := s.Delete(); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(); err != nil {
		t.Errorf("deleting twice: %v", err)
	}
}

func TestStoreRefusesBadContent(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	good := sample(t)
	bad := map[string]func(c *Credentials){
		"no refresh token":        func(c *Credentials) { c.RefreshToken = "" },
		"no key":                  func(c *Credentials) { c.DPoPKey = nil },
		"issuer not the server's": func(c *Credentials) { c.Issuer = "https://evil.example/t/acme" },
		"server with a path":      func(c *Credentials) { c.Server = "https://tessera.example/x"; c.Issuer = c.Server + "/t/acme" },
		"server not http(s)":      func(c *Credentials) { c.Server = "ftp://tessera.example"; c.Issuer = c.Server + "/t/acme" },
	}
	for name, mut := range bad {
		c := *good
		mut(&c)
		b, _ := json.Marshal(c)
		c2 := Credentials{}
		_ = json.Unmarshal(b, &c2)
		c2.Version = CredentialsVersion
		raw, _ := json.Marshal(c2)
		if err := os.WriteFile(s.Path(), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, raw := range map[string]string{"not JSON": "{", "empty": "", "a list": "[]", "another version": `{"version":99}`} {
		if err := os.WriteFile(s.Path(), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a directory, a symlink to a looser file
	_ = os.Remove(s.Path())
	if err := os.Mkdir(s.Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Error("a directory was accepted")
	}
	_ = os.Remove(s.Path())
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loose, s.Path()); err != nil {
		t.Skip("no symlinks")
	}
	if _, err := s.Load(); err == nil {
		t.Error("a link to a world-readable file was accepted")
	}
}

func TestKeyMustBeP256(t *testing.T) {
	c := sample(t)
	c.DPoPKey = json.RawMessage(`{"kty":"oct","k":"c2VjcmV0"}`)
	if _, err := c.Key(); err == nil {
		t.Error("a symmetric key was accepted")
	}
	c.DPoPKey = json.RawMessage(`{"kty":"EC","crv":"P-384","x":"","y":""}`)
	if _, err := c.Key(); err == nil {
		t.Error("a broken key was accepted")
	}
}

func TestLock(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "tessera")}
	unlock, err := s.Lock(time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// a second taker waits, then gives up
	start := time.Now()
	if _, err := s.Lock(150*time.Millisecond, time.Minute); err == nil || time.Since(start) < 100*time.Millisecond {
		t.Errorf("the lock was taken twice (%v)", err)
	}
	// it is free again after the release
	unlock()
	unlock2, err := s.Lock(time.Second, time.Minute)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	// a stale lock (its holder died) is broken
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(s.Dir, "credentials.lock"), old, old); err != nil {
		t.Fatal(err)
	}
	unlock3, err := s.Lock(time.Second, time.Minute)
	if err != nil {
		t.Fatalf("a stale lock: %v", err)
	}
	unlock3()
	unlock2()
}

func TestDefaultDir(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"override": {map[string]string{"TESSERA_CONFIG_DIR": "/x/y", "XDG_CONFIG_HOME": "/z", "HOME": "/h"}, "/x/y"},
		"xdg":      {map[string]string{"XDG_CONFIG_HOME": "/z", "HOME": "/h"}, "/z/tessera"},
		"home":     {map[string]string{"HOME": "/h"}, "/h/.config/tessera"},
	} {
		if got, err := DefaultDir(env(tc.env)); err != nil || got != tc.want {
			t.Errorf("%s: %q %v, want %q", name, got, err, tc.want)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	scheme, p := parseChallenge(`DPoP error="insufficient_user_authentication", error_description="This action needs a phishing-resistant sign-in in the last 15 minutes", acr_values="urn:tessera:acr:phr", max_age=900`)
	if scheme != "DPoP" || p["error"] != "insufficient_user_authentication" || p["acr_values"] != "urn:tessera:acr:phr" ||
		p["max_age"] != "900" || !strings.Contains(p["error_description"], "15 minutes") {
		t.Errorf("%q %v", scheme, p)
	}
	_, p = parseChallenge(`DPoP error="invalid_token", error_description="a \"quoted\" word, with a comma", algs="ES256 EdDSA"`)
	if p["error"] != "invalid_token" || p["error_description"] != `a "quoted" word, with a comma` || p["algs"] != "ES256 EdDSA" {
		t.Errorf("%v", p)
	}
	for _, in := range []string{"", "Bearer", `DPoP error`, `DPoP =`, `DPoP error="unterminated`, `DPoP ,,,`} {
		parseChallenge(in) // must not panic
	}
}

func TestNormalizeServer(t *testing.T) {
	for in, want := range map[string]string{"https://tessera.example": "https://tessera.example", "https://tessera.example/": "https://tessera.example",
		" http://localhost:5173 ": "http://localhost:5173"} {
		if got, err := NormalizeServer(in); err != nil || got != want {
			t.Errorf("NormalizeServer(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "tessera.example", "ftp://x", "https://u:p@x", "https://x/path", "https://x?q=1", "https://x#f", "https://"} {
		if got, err := NormalizeServer(in); err == nil {
			t.Errorf("NormalizeServer(%q) = %q, want an error", in, got)
		}
	}
}

func TestPrintable(t *testing.T) {
	if got := printable("ok\x1b[31mred\x07\r\n\x00end"); got != "ok[31mredend" {
		t.Errorf("printable = %q", got)
	}
	if got := (&OAuthError{Code: "x", Description: "a\x1bb"}).Error(); strings.ContainsRune(got, 0x1b) {
		t.Errorf("OAuthError leaks a control character: %q", got)
	}
}
