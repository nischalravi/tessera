package config_test

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var testKEK = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// safeProd is a production configuration that passes every guard rail.
func safeProd() map[string]string {
	return map[string]string{
		"TESSERA_ENV":             "prod",
		"TESSERA_PUBLIC_URL":      "https://tessera.example.com",
		"TESSERA_KEK":             testKEK,
		"TESSERA_AUDIT_ANCHOR":    "s3://anchors/tessera",
		"TESSERA_TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.10, 2001:db8::/32",
	}
}

func with(base map[string]string, kv ...string) map[string]string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "<unset>" {
			delete(m, kv[i])
		} else {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

func TestSafeProdStarts(t *testing.T) {
	c, err := config.Load(env(safeProd()))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsProd() || c.OutboundAllowLoopback || !c.CookieSecure || c.DevIdPURL != "" || len(c.CORSOrigins) != 0 ||
		len(c.TrustedProxies) != 3 || !c.FrozenNow.IsZero() {
		t.Errorf("unexpected prod config: %+v", c)
	}
	if c.APIAudience != "https://tessera.example.com/api" || c.RPID != "tessera.example.com" {
		t.Errorf("derived values: aud=%s rp_id=%s", c.APIAudience, c.RPID)
	}
	if _, err := c.Sealer(""); err != nil {
		t.Error(err)
	}
}

// TestProdRefusesEachUnsafeSetting: every guard rail of design §18.4, one
// unsafe setting at a time on top of an otherwise safe prod configuration.
func TestProdRefusesEachUnsafeSetting(t *testing.T) {
	cases := []struct {
		name string
		kv   []string
		want string
	}{
		{"public URL plain http", []string{"TESSERA_PUBLIC_URL", "http://tessera.example.com"}, "TESSERA_PUBLIC_URL must be https"},
		{"public URL missing", []string{"TESSERA_PUBLIC_URL", "<unset>"}, "TESSERA_PUBLIC_URL is required"},
		{"public URL with userinfo", []string{"TESSERA_PUBLIC_URL", "https://u:p@tessera.example.com"}, "TESSERA_PUBLIC_URL"},
		{"cookie not secure", []string{"TESSERA_COOKIE_SECURE", "false"}, "TESSERA_COOKIE_SECURE must be true"},
		{"no KEK", []string{"TESSERA_KEK", "<unset>"}, "a KEK is required"},
		{"KEK wrong length", []string{"TESSERA_KEK", base64.StdEncoding.EncodeToString([]byte("short"))}, "TESSERA_KEK: must decode to 32 bytes"},
		{"KEK not base64", []string{"TESSERA_KEK", "not base64!"}, "TESSERA_KEK: not valid base64"},
		{"KEK twice", []string{"TESSERA_KEK_FILE", "/nonexistent"}, "only one of TESSERA_KEK and TESSERA_KEK_FILE"},
		{"KEK file missing", []string{"TESSERA_KEK", "<unset>", "TESSERA_KEK_FILE", "/nonexistent/kek"}, "TESSERA_KEK_FILE"},
		{"wildcard CORS", []string{"TESSERA_CORS_ORIGINS", "*"}, "TESSERA_CORS_ORIGINS must be empty"},
		{"wildcard CORS in a list", []string{"TESSERA_CORS_ORIGINS", "https://a.example.com, https://*.example.com"}, "TESSERA_CORS_ORIGINS must be empty"},
		{"null CORS origin", []string{"TESSERA_CORS_ORIGINS", "null"}, "TESSERA_CORS_ORIGINS must be empty"},
		{"plain http CORS origin", []string{"TESSERA_CORS_ORIGINS", "http://tessera.example.com"}, "TESSERA_CORS_ORIGINS must be empty"},
		{"any CORS origin in prod", []string{"TESSERA_CORS_ORIGINS", "https://other.example.com"}, "TESSERA_CORS_ORIGINS must be empty"},
		{"same-origin CORS origin in prod", []string{"TESSERA_CORS_ORIGINS", "https://tessera.example.com"}, "TESSERA_CORS_ORIGINS must be empty"},
		{"frozen clock", []string{"TESSERA_NOW", "2026-01-01T00:00:00Z"}, "TESSERA_NOW must not be set"},
		{"trusted proxies 0.0.0.0/0", []string{"TESSERA_TRUSTED_PROXIES", "0.0.0.0/0"}, "trusts every address"},
		{"trusted proxies ::/0", []string{"TESSERA_TRUSTED_PROXIES", "10.0.0.0/8,::/0"}, "trusts every address"},
		{"trusted proxies broader than /8", []string{"TESSERA_TRUSTED_PROXIES", "10.0.0.0/7"}, "broader than /8"},
		{"trusted proxies broader than /32", []string{"TESSERA_TRUSTED_PROXIES", "2001:db8::/31"}, "broader than /32"},
		{"trusted proxies mapped IPv4 broader than /8", []string{"TESSERA_TRUSTED_PROXIES", "::ffff:0:0/96"}, "broader than /104"},
		{"outbound loopback", []string{"TESSERA_OUTBOUND_ALLOW_LOOPBACK", "true"}, "TESSERA_OUTBOUND_ALLOW_LOOPBACK must be false"},
		{"dev IdP URL set", []string{"TESSERA_DEV_IDP_URL", "http://127.0.0.1:8001"}, "TESSERA_DEV_IDP_URL must not be set"},
		{"dev login opt-in", []string{"TESSERA_DEV_LOGIN", "1"}, "TESSERA_DEV_LOGIN must not be set"},
		{"file audit anchor", []string{"TESSERA_AUDIT_ANCHOR", "file://server/var/audit-anchors.jsonl"}, "must not be file://"},
		{"audit anchor missing", []string{"TESSERA_AUDIT_ANCHOR", "<unset>"}, "TESSERA_AUDIT_ANCHOR is required"},
		{"access token TTL too long", []string{"TESSERA_AT_TTL_SECONDS", "901"}, "TESSERA_AT_TTL_SECONDS"},
		{"device code TTL too long", []string{"TESSERA_DEVICE_CODE_TTL_SECONDS", "601"}, "TESSERA_DEVICE_CODE_TTL_SECONDS"},
		{"bad boolean", []string{"TESSERA_COOKIE_SECURE", "maybe"}, "not a boolean"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := config.Load(env(with(safeProd(), c.kv...)))
			if err == nil {
				t.Fatalf("prod started with %v: %v", c.kv, cfg)
			}
			if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "refusing to start with TESSERA_ENV=prod") {
				t.Errorf("error %q does not name %q", err, c.want)
			}
		})
	}
}

// TestProdReportsEveryProblem: one refusal lists all violations, so an
// operator fixes them in one pass.
func TestProdReportsEveryProblem(t *testing.T) {
	_, err := config.Load(env(map[string]string{"TESSERA_ENV": "prod", "TESSERA_CORS_ORIGINS": "*",
		"TESSERA_OUTBOUND_ALLOW_LOOPBACK": "1"}))
	if err == nil {
		t.Fatal("started")
	}
	for _, want := range []string{"TESSERA_PUBLIC_URL", "a KEK is required", "TESSERA_CORS_ORIGINS must be empty", "OUTBOUND_ALLOW_LOOPBACK", "TESSERA_AUDIT_ANCHOR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestInvalidEnvRefused(t *testing.T) {
	for _, v := range []string{"DEV", "production", "Prod", " dev"} {
		if _, err := config.Load(env(map[string]string{"TESSERA_ENV": v})); err == nil ||
			!strings.Contains(err.Error(), "TESSERA_ENV=dev") {
			t.Errorf("TESSERA_ENV=%q: %v", v, err)
		}
	}
}

// TestDevDefaults: the dev settings that prod forbids are the dev defaults,
// and loading them has no side effects.
func TestDevDefaults(t *testing.T) {
	for _, e := range []string{"", "dev"} {
		c, err := config.Load(env(map[string]string{"TESSERA_ENV": e}))
		if err != nil {
			t.Fatal(err)
		}
		if c.Env != config.Dev || c.IsProd() || !c.OutboundAllowLoopback || c.PublicURL != "http://localhost:5173" ||
			c.DevIdPURL == "" || !slices.Equal(c.CORSOrigins, []string{"http://localhost:5173", "http://127.0.0.1:5173"}) ||
			c.AccessTokenTTLSeconds != 600 || c.DeviceCodeTTLSeconds != 300 || c.DB != "tessera.db" {
			t.Errorf("dev defaults: %+v", c)
		}
	}
	c, err := config.Load(env(map[string]string{"UI_PORT": "5210", "TESSERA_DB": "sqlite:///tmp/x.db"}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.CORSOrigins, []string{"http://localhost:5210", "http://127.0.0.1:5210"}) || c.DB != "tmp/x.db" {
		t.Errorf("UI_PORT / TESSERA_DB: %v %s", c.CORSOrigins, c.DB)
	}
	// dev does not apply the prod guard rails, but still rejects malformed values
	if _, err := config.Load(env(map[string]string{"TESSERA_CORS_ORIGINS": "*", "TESSERA_COOKIE_SECURE": "false"})); err != nil {
		t.Errorf("dev refused prod-only rules: %v", err)
	}
	if _, err := config.Load(env(map[string]string{"TESSERA_AT_TTL_SECONDS": "3600"})); err == nil {
		t.Error("dev accepted an access-token TTL above the maximum")
	}
	if _, err := config.Load(env(map[string]string{"TESSERA_TRUSTED_PROXIES": "10.0.0.0/8, nonsense"})); err == nil {
		t.Error("dev accepted a malformed trusted proxy")
	}
	if _, err := config.Load(env(map[string]string{"TESSERA_TRUSTED_PROXIES": "0.0.0.0/0"})); err == nil {
		t.Error("dev accepted a trusted proxy prefix of /0")
	}
	if _, err := config.Load(env(map[string]string{"TESSERA_NOW": "yesterday"})); err == nil {
		t.Error("dev accepted a malformed TESSERA_NOW")
	}
	if _, err := config.Load(env(map[string]string{"TESSERA_AUDIT_ANCHOR": "/var/anchors.jsonl"})); err == nil {
		t.Error("dev accepted an audit anchor that is not a file:// or s3:// URL")
	}
}

// TestAnchorURL: dev anchors next to the database unless TESSERA_AUDIT_ANCHOR
// says otherwise; prod uses only the configured sink.
func TestAnchorURL(t *testing.T) {
	c, err := config.Load(env(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if got, want := c.AnchorURL(filepath.Join(dir, "tessera.db")), "file://"+filepath.ToSlash(filepath.Join(dir, "var", "audit-anchors.jsonl")); got != want {
		t.Errorf("dev anchor %q, want %q", got, want)
	}
	c, err = config.Load(env(map[string]string{"TESSERA_AUDIT_ANCHOR": "file:///srv/anchors.jsonl"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.AnchorURL("x.db"); got != "file:///srv/anchors.jsonl" {
		t.Errorf("configured anchor %q", got)
	}
	p, err := config.Load(env(safeProd()))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.AnchorURL("x.db"); got != "s3://anchors/tessera" {
		t.Errorf("prod anchor %q", got)
	}
}

// TestClock: TESSERA_NOW freezes the clock in dev; unset, the wall clock runs.
func TestClock(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_NOW": "2026-10-08T09:30:00"}))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	if got := c.Clock()(); !got.Equal(want) {
		t.Errorf("frozen clock = %v, want %v", got, want)
	}
	c, err = config.Load(env(map[string]string{"TESSERA_ENV": "dev"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Clock()(); time.Since(got) > time.Minute || time.Since(got) < -time.Minute {
		t.Errorf("wall clock = %v", got)
	}
}

func TestDevKEKGeneratedOnceWithMode0600(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev"}))
	if err != nil {
		t.Fatal(err)
	}
	path := config.DevKEKPath(filepath.Join(t.TempDir(), "tessera.db"))
	s1, err := c.Sealer(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("dev KEK mode %04o, want 0600", fi.Mode().Perm())
	}
	aad := []byte("t|c|x")
	sealed, err := s1.Seal([]byte("v"), aad)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := c.Sealer(path) // second start reuses the same key
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Open(sealed, aad); err != nil {
		t.Errorf("the dev KEK changed between starts: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sealer(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("a world-readable KEK file was accepted: %v", err)
	}
}

func TestKEKFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kek")
	if err := os.WriteFile(path, []byte(testKEK+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(env(with(safeProd(), "TESSERA_KEK", "<unset>", "TESSERA_KEK_FILE", path)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sealer(""); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(env(with(safeProd(), "TESSERA_KEK", "<unset>", "TESSERA_KEK_FILE", path))); err == nil {
		t.Error("prod accepted a group-readable KEK file")
	}
}

func TestConfigNeverPrintsKEK(t *testing.T) {
	c, err := config.Load(env(safeProd()))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(testKEK)
	var logs strings.Builder
	slog.New(slog.NewTextHandler(&logs, nil)).Info("config", "cfg", c)
	for _, out := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprintf("%v", *c),
		fmt.Sprintf("%+v", *c), fmt.Sprintf("%#v", *c), logs.String()} {
		if strings.Contains(out, testKEK) || strings.Contains(out, string(raw)) || strings.Contains(out, fmt.Sprintf("%x", raw)) ||
			strings.Contains(out, fmt.Sprint(raw)) {
			t.Errorf("KEK printed: %s", out)
		}
	}
}

// TestTestEnvAndInsecureCookie: TESSERA_ENV=test is a non-production
// environment; the insecure-cookie fallback is allowed only in dev on a
// localhost public URL (§11).
func TestTestEnvAndInsecureCookie(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "test"}))
	if err != nil || c.Env != config.Test || c.IsProd() || c.PublicOrigin() != "http://localhost:5173" {
		t.Fatalf("test env: %+v %v", c, err)
	}
	for _, tc := range []struct {
		env map[string]string
		ok  bool
	}{
		{map[string]string{"TESSERA_ENV": "dev", "TESSERA_COOKIE_SECURE": "false"}, true},
		{map[string]string{"TESSERA_ENV": "dev", "TESSERA_COOKIE_SECURE": "false", "TESSERA_PUBLIC_URL": "http://127.0.0.1:5173"}, true},
		{map[string]string{"TESSERA_ENV": "dev", "TESSERA_COOKIE_SECURE": "false", "TESSERA_PUBLIC_URL": "http://tessera.test.example"}, false},
		{map[string]string{"TESSERA_ENV": "test", "TESSERA_COOKIE_SECURE": "false"}, false},
	} {
		_, err := config.Load(env(tc.env))
		if (err == nil) != tc.ok {
			t.Errorf("%v: %v, want ok=%t", tc.env, err, tc.ok)
		}
	}
	c, err = config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_PUBLIC_URL": "https://tessera.example.com/app"}))
	if err != nil || c.PublicOrigin() != "https://tessera.example.com" {
		t.Errorf("public origin %q %v", c.PublicOrigin(), err)
	}
}
