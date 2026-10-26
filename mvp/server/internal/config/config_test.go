package config_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/kekwrap"
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

// TestAWSAllowStaticKeys: stored AWS access keys are allowed by default in dev
// and test, off by default in prod, and prod refuses the flag being on.
func TestAWSAllowStaticKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"dev default", map[string]string{"TESSERA_ENV": "dev"}, true},
		{"dev off", map[string]string{"TESSERA_ENV": "dev", "TESSERA_AWS_ALLOW_STATIC_KEYS": "false"}, false},
		{"test default", map[string]string{"TESSERA_ENV": "test"}, true},
	} {
		c, err := config.Load(env(tc.env))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if c.AWSAllowStaticKeys != tc.want {
			t.Errorf("%s: AWSAllowStaticKeys = %t, want %t", tc.name, c.AWSAllowStaticKeys, tc.want)
		}
	}
	c, err := config.Load(env(safeProd()))
	if err != nil {
		t.Fatal(err)
	}
	if c.AWSAllowStaticKeys {
		t.Error("prod default allows static AWS keys")
	}
	kv := safeProd()
	kv["TESSERA_AWS_ALLOW_STATIC_KEYS"] = "1"
	if _, err := config.Load(env(kv)); err == nil || !strings.Contains(err.Error(), "TESSERA_AWS_ALLOW_STATIC_KEYS must not be set") {
		t.Errorf("prod with static keys: err = %v", err)
	}
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
		{"public URL with a port", []string{"TESSERA_PUBLIC_URL", "https://tessera.example.com:8443"}, "must not have a port"},
		{"cookie not secure", []string{"TESSERA_COOKIE_SECURE", "false"}, "TESSERA_COOKIE_SECURE must be true"},
		{"AWS static keys allowed", []string{"TESSERA_AWS_ALLOW_STATIC_KEYS", "true"}, "TESSERA_AWS_ALLOW_STATIC_KEYS must not be set"},
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
		{"auth burst over the prod cap", []string{"TESSERA_AUTH_RATE_BURST", "5000"}, "TESSERA_AUTH_RATE_BURST must be at most 300"},
		{"anonymous burst over the prod cap", []string{"TESSERA_ANON_RATE_BURST", "5000"}, "TESSERA_ANON_RATE_BURST must be at most 2000"},
		{"client rate limit off", []string{"TESSERA_API_CLIENT_RATE_PER_MINUTE", "0"}, "TESSERA_API_CLIENT_RATE_ALLOW_OFF"},
		{"trusted proxies 0.0.0.0/0", []string{"TESSERA_TRUSTED_PROXIES", "0.0.0.0/0"}, "trusts every address"},
		{"trusted proxies ::/0", []string{"TESSERA_TRUSTED_PROXIES", "10.0.0.0/8,::/0"}, "trusts every address"},
		{"trusted proxies broader than /8", []string{"TESSERA_TRUSTED_PROXIES", "10.0.0.0/7"}, "broader than /8"},
		{"trusted proxies broader than /32", []string{"TESSERA_TRUSTED_PROXIES", "2001:db8::/31"}, "broader than /32"},
		{"trusted proxies mapped IPv4 broader than /8", []string{"TESSERA_TRUSTED_PROXIES", "::ffff:0:0/96"}, "broader than /104"},
		{"outbound loopback", []string{"TESSERA_OUTBOUND_ALLOW_LOOPBACK", "true"}, "TESSERA_OUTBOUND_ALLOW_LOOPBACK must be false"},
		{"safedial allowlist", []string{"TESSERA_SAFEDIAL_ALLOW", "192.168.1.10:636"}, "TESSERA_SAFEDIAL_ALLOW must not be set"},
		{"simulated rotation adapter", []string{"TESSERA_ROTATION_FAKE_ADAPTERS", "true"}, "TESSERA_ROTATION_FAKE_ADAPTERS must be false"},
		{"weaker step-up policy", []string{"TESSERA_STEPUP_ALLOW_WEAKER", "true"}, "TESSERA_STEPUP_ALLOW_WEAKER must be false"},
		{"step-up bypass", []string{"TESSERA_STEPUP_BYPASS", "true"}, "TESSERA_STEPUP_BYPASS must be false"},
		{"dev IdP URL set", []string{"TESSERA_DEV_IDP_URL", "http://127.0.0.1:8001"}, "TESSERA_DEV_IDP_URL must not be set"},
		{"dev fake provisioning target", []string{"TESSERA_DEV_FAKE_TARGET", "1"}, "TESSERA_DEV_FAKE_TARGET must not be set"},
		{"file audit anchor", []string{"TESSERA_AUDIT_ANCHOR", "file://server/var/audit-anchors.jsonl"}, "must not be file://"},
		{"audit anchor missing", []string{"TESSERA_AUDIT_ANCHOR", "<unset>"}, "TESSERA_AUDIT_ANCHOR is required"},
		{"file audit anchor, upper case", []string{"TESSERA_AUDIT_ANCHOR", "FILE:///srv/a.jsonl"}, "TESSERA_AUDIT_ANCHOR"},
		{"audit anchor S3 upper case", []string{"TESSERA_AUDIT_ANCHOR", "S3://anchors/t"}, "TESSERA_AUDIT_ANCHOR"},
		{"audit anchor s3 without a bucket", []string{"TESSERA_AUDIT_ANCHOR", "s3://"}, "must be an s3://bucket/prefix URL"},
		{"audit anchor https", []string{"TESSERA_AUDIT_ANCHOR", "https://anchors.example.com/"}, "TESSERA_AUDIT_ANCHOR"},
		{"access token TTL too long", []string{"TESSERA_AT_TTL_SECONDS", "901"}, "TESSERA_AT_TTL_SECONDS"},
		{"device code TTL too long", []string{"TESSERA_DEVICE_CODE_TTL_SECONDS", "601"}, "TESSERA_DEVICE_CODE_TTL_SECONDS"},
		{"bad boolean", []string{"TESSERA_COOKIE_SECURE", "maybe"}, "not a boolean"},
		{"dev mail sink", []string{"TESSERA_NOTIFY_EMAIL", "dev"}, "dev sink"},
		{"SMTP without TLS", []string{"TESSERA_SMTP_HOST", "smtp.example.com", "TESSERA_SMTP_FROM", "t@example.com", "TESSERA_SMTP_TLS", "none"},
			"TESSERA_SMTP_TLS=none"},
		{"SMTP login without a sealed password", []string{"TESSERA_SMTP_HOST", "smtp.example.com", "TESSERA_SMTP_FROM", "t@example.com",
			"TESSERA_SMTP_USERNAME", "u"}, "TESSERA_SMTP_PASSWORD_SEALED is required"},
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
func TestGroupsSyncBudget(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev"}))
	if err != nil || c.GroupsSyncBudget != 5000 {
		t.Fatalf("default = %v, %v; want 5000", c, err)
	}
	c, err = config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_GROUPS_SYNC_BUDGET": "250"}))
	if err != nil || c.GroupsSyncBudget != 250 {
		t.Errorf("set = %v, %v; want 250", c, err)
	}
	for _, bad := range []string{"0", "-1", "lots", "99999999999"} {
		if _, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_GROUPS_SYNC_BUDGET": bad})); err == nil {
			t.Errorf("TESSERA_GROUPS_SYNC_BUDGET=%q was accepted", bad)
		}
	}
}

func TestGroupsRetentionDays(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev"}))
	if err != nil || c.GroupsRetentionDays != 7*365 {
		t.Fatalf("default = %v, %v; want 7 years", c, err)
	}
	c, err = config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_GROUPS_RETENTION_DAYS": "400"}))
	if err != nil || c.GroupsRetentionDays != 400 {
		t.Errorf("set = %v, %v; want 400", c, err)
	}
	for _, bad := range []string{"0", "29", "-1", "years", "99999"} {
		if _, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_GROUPS_RETENTION_DAYS": bad})); err == nil {
			t.Errorf("TESSERA_GROUPS_RETENTION_DAYS=%q was accepted", bad)
		}
	}
}

// TestLoaderDataDir: file sources of group loaders are off unless the data
// directory is set, and it is refused if it is relative or contains the database.
func TestLoaderDataDir(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev"}))
	if err != nil || c.LoaderDataDir != "" {
		t.Fatalf("default = %q, %v; want off", c.LoaderDataDir, err)
	}
	dir := t.TempDir()
	c, err = config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_LOADER_DATA_DIR": dir, "TESSERA_DB": filepath.Join(t.TempDir(), "t.db")}))
	if err != nil || c.LoaderDataDir != dir {
		t.Errorf("set = %q, %v; want %s", c.LoaderDataDir, err, dir)
	}
	for name, vars := range map[string]map[string]string{
		"relative":         {"TESSERA_LOADER_DATA_DIR": "data/loaders"},
		"holds the db":     {"TESSERA_LOADER_DATA_DIR": dir, "TESSERA_DB": filepath.Join(dir, "t.db")},
		"holds the db too": {"TESSERA_LOADER_DATA_DIR": dir, "TESSERA_DB": filepath.Join(dir, "sub", "t.db")},
		"is a parent":      {"TESSERA_LOADER_DATA_DIR": filepath.Dir(dir), "TESSERA_DB": filepath.Join(dir, "t.db")},
	} {
		vars["TESSERA_ENV"] = "dev"
		if _, err := config.Load(env(vars)); err == nil {
			t.Errorf("%s: TESSERA_LOADER_DATA_DIR was accepted", name)
		}
	}
	// a sibling directory that shares a name prefix is not inside it
	other := dir + "-other"
	if _, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_LOADER_DATA_DIR": dir, "TESSERA_DB": filepath.Join(other, "t.db")})); err != nil {
		t.Errorf("a database next to the directory was refused: %v", err)
	}
}

func TestGroupsProvSQLDir(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev"}))
	if err != nil || c.GroupsProvSQLDir != "" {
		t.Fatalf("default = %q, %v; want the SQL target off", c.GroupsProvSQLDir, err)
	}
	c, err = config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_GROUPS_PROV_SQL_DIR": " /var/lib/tessera/prov "}))
	if err != nil || c.GroupsProvSQLDir != "/var/lib/tessera/prov" {
		t.Errorf("set = %q, %v", c.GroupsProvSQLDir, err)
	}
}

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

// TestArchiveSettings (issue #298): where the archive lives, and what prod refuses.
func TestArchiveSettings(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "tessera.db")
	dev, err := config.Load(env(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := dev.ArchiveDirFor(db), filepath.Join(dir, "var", "archive"); got != want {
		t.Errorf("dev archive dir %q, want %q", got, want)
	}
	c, err := config.Load(env(map[string]string{"TESSERA_BACKUP_DIR": "/srv/backups"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ArchiveDirFor(db); got != filepath.Join("/srv/backups", "archive") {
		t.Errorf("archive dir with a backup dir %q", got)
	}
	c, err = config.Load(env(map[string]string{"TESSERA_BACKUP_DIR": "/srv/backups", "TESSERA_ARCHIVE_DIR": "/srv/arch"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ArchiveDirFor(db); got != "/srv/arch" {
		t.Errorf("archive dir %q", got)
	}
	// prod has no implicit archive: unset means off
	p, err := config.Load(env(safeProd()))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ArchiveDirFor(db); got != "" {
		t.Errorf("prod archive dir %q, want none", got)
	}
	for _, bad := range []string{"ftp://x/y", "https://user:pw@host/p", "https://host/p?x=1", "https://host/p#f", "host/path", "https:///p"} {
		if _, err := config.Load(env(map[string]string{"TESSERA_ARCHIVE_URL": bad})); err == nil {
			t.Errorf("TESSERA_ARCHIVE_URL=%q accepted", bad)
		}
	}
	if _, err := config.Load(env(map[string]string{"TESSERA_ARCHIVE_URL": "http://objects.internal:9000/archive"})); err != nil {
		t.Errorf("an http archive URL is refused in dev: %v", err)
	}
	prod := safeProd()
	prod["TESSERA_ARCHIVE_URL"] = "http://objects.internal:9000/archive"
	if _, err := config.Load(env(prod)); err == nil {
		t.Error("an http archive URL is accepted in prod")
	}
	prod["TESSERA_ARCHIVE_URL"] = "https://objects.example.com/archive"
	if _, err := config.Load(env(prod)); err == nil || !strings.Contains(err.Error(), "TESSERA_ARCHIVE_TOKEN_SEALED") {
		t.Errorf("an archive URL without credentials is accepted in prod: %v", err)
	}
	prod["TESSERA_ARCHIVE_TOKEN_SEALED"] = "%%%"
	if _, err := config.Load(env(prod)); err == nil {
		t.Error("a non-base64 sealed token is accepted")
	}
	prod["TESSERA_ARCHIVE_TOKEN_SEALED"] = "c2VhbGVk"
	if p, err := config.Load(env(prod)); err != nil || p.ArchiveURL != "https://objects.example.com/archive" {
		t.Errorf("an https archive URL with a token in prod: %v", err)
	}
	if _, err := config.Load(env(map[string]string{"TESSERA_ARCHIVE_TOKEN_SEALED": "c2VhbGVk"})); err == nil {
		t.Error("a token without an archive URL is accepted")
	}
}

// TestPostgresDSN: a postgres:// TESSERA_DB works in dev (dev files go in the
// working directory, not in a directory named after the URL), and production
// refuses a DSN without TLS, a missing or owner-equal TESSERA_DB_APP (the
// application must log in as its own role, #430) and the retired app_role
// option, without echoing a DSN (it holds the password).
func TestPostgresDSN(t *testing.T) {
	dsn := "postgres://tessera_owner:s3cret-pw@db.example.com:5432/tessera?sslmode=require"
	appDSN := "postgres://tessera_app:s3cret-app@db.example.com:5432/tessera?sslmode=require"
	if _, err := config.Load(env(map[string]string{"TESSERA_DB": dsn})); err != nil {
		t.Fatalf("dev with a postgres DSN: %v", err)
	}
	wd, _ := filepath.Abs(".")
	if got, want := config.DevKEKPath(dsn), filepath.Join(".", "var", "dev-kek"); got != want {
		t.Errorf("dev KEK path %q, want %q", got, want)
	}
	if got, want := config.DevAnchorURL(dsn), "file://"+filepath.ToSlash(filepath.Join(wd, "var", "audit-anchors.jsonl")); got != want {
		t.Errorf("dev anchor %q, want %q", got, want)
	}
	prod := with(with(safeProd(), "TESSERA_DB", dsn), "TESSERA_DB_APP", appDSN)
	c, err := config.Load(env(prod))
	if err != nil {
		t.Errorf("prod with a safe DSN pair: %v", err)
	} else if c.DBApp != appDSN {
		t.Errorf("DBApp %q", c.DBApp)
	}
	for name, tc := range map[string]struct{ key, dsn, want string }{
		"no sslmode":         {"TESSERA_DB", "postgres://o:s3cret-pw@db/tessera", "sslmode must be require"},
		"sslmode disable":    {"TESSERA_DB", "postgres://o:s3cret-pw@db/tessera?sslmode=disable", "sslmode must be require"},
		"sslmode prefer":     {"TESSERA_DB", "postgres://o:s3cret-pw@db/tessera?sslmode=prefer", "sslmode must be require"},
		"app_role retired":   {"TESSERA_DB", dsn + "&app_role=tessera_app", "TESSERA_DB_APP"},
		"no app DSN":         {"TESSERA_DB_APP", "", "is required"},
		"app DSN not pg":     {"TESSERA_DB_APP", "/var/lib/app.db", "not a valid postgres"},
		"app DSN no TLS":     {"TESSERA_DB_APP", "postgres://tessera_app:s3cret-app@db/tessera?sslmode=disable", "sslmode must be require"},
		"app DSN is owner":   {"TESSERA_DB_APP", "postgres://tessera_owner:s3cret-pw@db.example.com/tessera?sslmode=require", "different login"},
		"app DSN no user":    {"TESSERA_DB_APP", "postgres://db.example.com/tessera?sslmode=require", "name the application login"},
		"app DSN app_role":   {"TESSERA_DB_APP", appDSN + "&app_role=x", "app_role is not supported"},
		"privileged allowed": {"TESSERA_DEV_DB_ALLOW_PRIVILEGED_APP", "true", "TESSERA_DEV_DB_ALLOW_PRIVILEGED_APP must not be set"},
	} {
		_, err := config.Load(env(with(prod, tc.key, tc.dsn)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		} else if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: the error echoes a DSN password: %v", name, err)
		}
	}
	// SQLite in prod needs no app DSN.
	if _, err := config.Load(env(with(safeProd(), "TESSERA_DB", "/var/lib/tessera/t.db"))); err != nil {
		t.Errorf("prod with SQLite: %v", err)
	}
	if c, err := config.Load(env(map[string]string{"TESSERA_DEV_DB_ALLOW_PRIVILEGED_APP": "true"})); err != nil || !c.DBAllowPrivilegedApp {
		t.Errorf("dev override: %v", err)
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

// TestDevKEKAtomicWrite (L8): the dev KEK is written to a temp file and
// linked into place, so no temp file is left behind, concurrent first
// starts all end up with the one KEK that was placed, and an existing
// (even broken) KEK file is never replaced.
func TestDevKEKAtomicWrite(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev"}))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "var")
	path := filepath.Join(dir, "dev-kek")
	const n = 16
	var wg sync.WaitGroup
	sealed := make([][]byte, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := c.Sealer(path)
			if err != nil {
				errs[i] = err
				return
			}
			sealed[i], errs[i] = s.Seal([]byte("v"), []byte("t|c|x"))
		}()
	}
	wg.Wait()
	final, err := c.Sealer(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("start %d: %v", i, errs[i])
		}
		if _, err := final.Open(sealed[i], []byte("t|c|x")); err != nil {
			t.Errorf("start %d used another KEK than the one on disk", i)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "dev-kek" {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only dev-kek (no temp files)", names)
	}
	// an existing file is never overwritten, even a broken one
	broken := filepath.Join(t.TempDir(), "dev-kek")
	if err := os.WriteFile(broken, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sealer(broken); err == nil {
		t.Error("a broken KEK file was accepted")
	}
	if b, _ := os.ReadFile(broken); string(b) != "not a key\n" {
		t.Errorf("the broken KEK file was replaced: %q", b)
	}
	// a dangling symlink in its place: refused, not looped on or replaced
	dangling := filepath.Join(t.TempDir(), "dev-kek")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sealer(dangling); err == nil {
		t.Error("a dangling KEK symlink was accepted")
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
	// a Kubernetes secret volume is 0440 (or 0640) with the pod's fsGroup: the group may read it
	for _, mode := range []os.FileMode{0o440, 0o640, 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Load(env(with(safeProd(), "TESSERA_KEK", "<unset>", "TESSERA_KEK_FILE", path))); err != nil {
			t.Errorf("prod refused a KEK file with mode %04o owned by this process: %v", mode, err)
		}
	}
	// never: any access for others, or write access for the group
	for _, mode := range []os.FileMode{0o604, 0o644, 0o602, 0o660, 0o620, 0o666, 0o404} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Load(env(with(safeProd(), "TESSERA_KEK", "<unset>", "TESSERA_KEK_FILE", path))); err == nil {
			t.Errorf("prod accepted a KEK file with mode %04o", mode)
		}
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

// TestSafedialAllowDevOnly: the live-LDAP private-target allowlist is read in
// dev and refused in prod (the Directory Agent is the production path).
func TestSafedialAllowDevOnly(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_SAFEDIAL_ALLOW": " 192.168.1.10:636 "}))
	if err != nil || c.SafedialAllow != "192.168.1.10:636" {
		t.Fatalf("dev: %v %q", err, c.SafedialAllow)
	}
	if _, err := config.Load(env(with(safeProd(), "TESSERA_SAFEDIAL_ALLOW", "192.168.1.10:636"))); err == nil {
		t.Fatal("prod accepted TESSERA_SAFEDIAL_ALLOW")
	}
}

// TestAgentListenerConfig: the Directory Agent listener is mutual TLS only, so
// an address needs its certificate and key, and they need the address; prod
// accepts the complete set.
func TestAgentListenerConfig(t *testing.T) {
	c, err := config.Load(env(with(safeProd(), "TESSERA_AGENT_ADDR", ":8443", "TESSERA_AGENT_TLS_CERT", "/etc/t/a.crt", "TESSERA_AGENT_TLS_KEY", "/etc/t/a.key")))
	if err != nil || c.AgentAddr != ":8443" || c.AgentTLSCert != "/etc/t/a.crt" || c.AgentTLSKey != "/etc/t/a.key" {
		t.Fatalf("prod with a complete agent listener: %v %+v", err, c)
	}
	if c, err := config.Load(env(safeProd())); err != nil || c.AgentAddr != "" {
		t.Fatalf("no listener by default: %v", err)
	}
	for name, kv := range map[string][]string{
		"address only":      {"TESSERA_AGENT_ADDR", ":8443"},
		"address and cert":  {"TESSERA_AGENT_ADDR", ":8443", "TESSERA_AGENT_TLS_CERT", "/c"},
		"cert and key only": {"TESSERA_AGENT_TLS_CERT", "/c", "TESSERA_AGENT_TLS_KEY", "/k"},
	} {
		if _, err := config.Load(env(with(safeProd(), kv...))); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestExternalWorkerKinds (issue #302): serve stops running the listed worker
// kinds in-process; an unknown kind is refused (a typo must not silently leave
// work un-run), repeats collapse, and the default is to run everything here.
// Prod still refuses the private-network allowlist that remote agents replace.
func TestExternalWorkerKinds(t *testing.T) {
	c, err := config.Load(env(with(safeProd(), "TESSERA_EXTERNAL_WORKER_KINDS", " provision_push, connector_sync,provision_push ",
		"TESSERA_CONNECTOR_SYNC_SCHEDULE", "@every 15m")))
	if err != nil || !slices.Equal(c.ExternalWorkerKinds, []string{"connector_sync", "provision_push"}) || c.ConnectorSyncSchedule != "@every 15m" {
		t.Fatalf("prod with external kinds: %v %+v", err, c)
	}
	if c, err := config.Load(env(safeProd())); err != nil || len(c.ExternalWorkerKinds) != 0 || c.ConnectorSyncSchedule != "" {
		t.Fatalf("default runs every kind in-process: %v %+v", err, c)
	}
	if _, err := config.Load(env(with(safeProd(), "TESSERA_EXTERNAL_WORKER_KINDS", "connector_sync,jit_sweep"))); err == nil {
		t.Error("an unknown worker kind was accepted")
	}
	if _, err := config.Load(env(with(safeProd(), "TESSERA_SAFEDIAL_ALLOW", "10.0.0.0/8:389"))); err == nil {
		t.Error("prod accepted a private-network allowlist (private directories are reached through a remote agent)")
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
		// L8: only a localhost public URL, by exact host name
		{map[string]string{"TESSERA_ENV": "dev", "TESSERA_COOKIE_SECURE": "false", "TESSERA_PUBLIC_URL": "http://localhost.evil.example:5173"}, false},
		{map[string]string{"TESSERA_ENV": "dev", "TESSERA_COOKIE_SECURE": "false", "TESSERA_PUBLIC_URL": "http://127.0.0.2:5173"}, false},
		{map[string]string{"TESSERA_ENV": "dev", "TESSERA_COOKIE_SECURE": "false", "TESSERA_PUBLIC_URL": "http://10.0.0.5:5173"}, false},
		{map[string]string{"TESSERA_ENV": "dev", "TESSERA_COOKIE_SECURE": "false", "TESSERA_PUBLIC_URL": "http://[::ffff:7f00:1]:5173"}, false},
		{with(safeProd(), "TESSERA_COOKIE_SECURE", "false", "TESSERA_PUBLIC_URL", "http://localhost:5173"), false},
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

// The fake provisioning target is a dev tool: off by default, on in dev when asked.
func TestFakeTargetIsDevOnly(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{"TESSERA_ENV": "dev"}, false},
		{map[string]string{"TESSERA_ENV": "dev", "TESSERA_DEV_FAKE_TARGET": "1"}, true},
	} {
		c, err := config.Load(env(tc.env))
		if err != nil || c.FakeTarget != tc.want {
			t.Errorf("%v: FakeTarget = %v, %v; want %v", tc.env, c != nil && c.FakeTarget, err, tc.want)
		}
	}
}

// The fake OAuth app providers are a dev tool: prod refuses their base URL.
func TestDevOAuthFakeURLIsDevOnly(t *testing.T) {
	c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_DEV_OAUTH_FAKE_URL": "http://127.0.0.1:10000/"}))
	if err != nil || c.DevOAuthFakeURL != "http://127.0.0.1:10000" {
		t.Errorf("dev: %v, %v", c, err)
	}
	_, err = config.Load(env(with(safeProd(), "TESSERA_DEV_OAUTH_FAKE_URL", "http://127.0.0.1:10000")))
	if err == nil || !strings.Contains(err.Error(), "TESSERA_DEV_OAUTH_FAKE_URL") {
		t.Errorf("prod accepted the fake OAuth URL: %v", err)
	}
}

func TestDevOnlyURL(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://login.example.com/oauth2": false, "https://203.0.113.9/x": false, "not a url": false, "": false,
		"http://login.example.com": true, "https://localhost:8443": true, "https://api.localhost": true, "https://127.0.0.1:8001": true,
		"https://[::1]/x": true, "https://10.1.2.3": true, "https://192.168.0.5": true, "https://169.254.169.254": true,
	} {
		if got := config.DevOnlyURL(raw) != ""; got != want {
			t.Errorf("DevOnlyURL(%q) = %q, want dev-only %v", raw, config.DevOnlyURL(raw), want)
		}
	}
}

// TestMailConfig: the email sender defaults by environment, and SMTP needs a
// host and a from address.
func TestMailConfig(t *testing.T) {
	c, err := config.Load(env(safeProd()))
	if err != nil || c.Mail.Mode != config.MailOff {
		t.Errorf("prod default mail = %+v, %v; want off", c.Mail, err)
	}
	c, err = config.Load(env(with(safeProd(), "TESSERA_SMTP_HOST", "smtp.example.com", "TESSERA_SMTP_FROM", "Tessera <t@example.com>",
		"TESSERA_SMTP_USERNAME", "u", "TESSERA_SMTP_PASSWORD_SEALED", testKEK)))
	if err != nil || c.Mail.Mode != config.MailSMTP || c.Mail.Port != 587 || c.Mail.TLS != config.SMTPStartTLS {
		t.Errorf("prod smtp mail = %+v, %v", c.Mail, err)
	}
	if strings.Contains(c.Mail.String(), testKEK) {
		t.Error("Mail.String shows the sealed password")
	}
	for _, env0 := range []string{"dev", "test"} {
		c, err = config.Load(env(map[string]string{"TESSERA_ENV": env0}))
		if err != nil || c.Mail.Mode != config.MailDev || c.NotifyMaxAttempts != 6 || c.NotifyDigestHour != 8 {
			t.Errorf("%s default mail = %+v, %v", env0, c, err)
		}
	}
	for _, kv := range [][]string{
		{"TESSERA_NOTIFY_EMAIL", "smtp"},
		{"TESSERA_NOTIFY_EMAIL", "pigeon"},
		{"TESSERA_SMTP_HOST", "smtp.example.com"},
		{"TESSERA_SMTP_HOST", "smtp.example.com", "TESSERA_SMTP_FROM", "not an address"},
		{"TESSERA_SMTP_TLS", "ssl"},
		{"TESSERA_NOTIFY_MAX_ATTEMPTS", "0"},
		{"TESSERA_NOTIFY_DIGEST_HOUR", "24"},
	} {
		if _, err := config.Load(env(with(map[string]string{"TESSERA_ENV": "dev"}, kv...))); err == nil {
			t.Errorf("dev accepted %v", kv)
		}
	}
}

// /metrics is never public by default (issue #303): off in prod unless set,
// loopback in dev, and a prod address must be loopback or private.
func TestMetricsAddr(t *testing.T) {
	prod := func(kv ...string) map[string]string { return with(safeProd(), kv...) }
	// defaults
	if c, err := config.Load(env(prod())); err != nil || c.MetricsAddr != "" {
		t.Errorf("prod default: %q %v (want off)", c.MetricsAddr, err)
	}
	if c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev"})); err != nil || c.MetricsAddr != config.MetricsDefaultAddr || !c.MetricsAddrDefault {
		t.Errorf("dev default: %+v %v", c, err)
	}
	if c, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev", "TESSERA_METRICS_ADDR": "off"})); err != nil || c.MetricsAddr != "" {
		t.Errorf("dev off: %v", err)
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		ok   bool
	}{
		{"prod loopback", prod("TESSERA_METRICS_ADDR", "127.0.0.1:9464"), true},
		{"prod private", prod("TESSERA_METRICS_ADDR", "10.1.2.3:9464"), true},
		{"prod ULA v6", prod("TESSERA_METRICS_ADDR", "[fd00::1]:9464"), true},
		{"prod public ip", prod("TESSERA_METRICS_ADDR", "203.0.113.9:9464"), false},
		{"prod hostname", prod("TESSERA_METRICS_ADDR", "metrics.example.com:9464"), false},
		{"prod localhost name", prod("TESSERA_METRICS_ADDR", "localhost:9464"), false},
		{"prod wildcard", prod("TESSERA_METRICS_ADDR", "0.0.0.0:9464"), false},
		{"prod bare port", prod("TESSERA_METRICS_ADDR", ":9464"), false},
		{"prod v6 wildcard", prod("TESSERA_METRICS_ADDR", "[::]:9464"), false},
		{"prod wildcard opted in", prod("TESSERA_METRICS_ADDR", ":9464", "TESSERA_METRICS_ALLOW_WILDCARD", "true"), true},
		{"prod public even when wildcard flag set", prod("TESSERA_METRICS_ADDR", "203.0.113.9:9464", "TESSERA_METRICS_ALLOW_WILDCARD", "true"), false},
		{"prod bad port", prod("TESSERA_METRICS_ADDR", "10.0.0.1:0"), false},
		{"prod no port", prod("TESSERA_METRICS_ADDR", "10.0.0.1"), false},
		{"dev loopback", map[string]string{"TESSERA_ENV": "dev", "TESSERA_METRICS_ADDR": "127.0.0.1:9999"}, true},
		{"dev localhost", map[string]string{"TESSERA_ENV": "dev", "TESSERA_METRICS_ADDR": "localhost:9999"}, true},
		{"dev wildcard", map[string]string{"TESSERA_ENV": "dev", "TESSERA_METRICS_ADDR": ":9999"}, false},
		{"dev private", map[string]string{"TESSERA_ENV": "dev", "TESSERA_METRICS_ADDR": "192.168.1.5:9999"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := config.Load(env(tc.env))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err == nil && c.MetricsAddrDefault {
				t.Error("an explicit address is not the default")
			}
		})
	}
	if _, err := config.Load(env(with(safeProd(), "TESSERA_READY_MAX_LOOP_LAG_SECONDS", "5"))); err == nil {
		t.Error("lag threshold below 30s accepted")
	}
}

// The simulated secret-rotation adapter exists only where it cannot be mistaken for a real one.
func TestRotationFakeAdapters(t *testing.T) {
	for _, tc := range []struct {
		name string
		kv   map[string]string
		want bool
	}{
		{"dev default", map[string]string{"TESSERA_ENV": "dev"}, true},
		{"test default", map[string]string{"TESSERA_ENV": "test"}, true},
		{"dev switched off", map[string]string{"TESSERA_ENV": "dev", "TESSERA_ROTATION_FAKE_ADAPTERS": "0"}, false},
		{"prod default", safeProd(), false},
	} {
		cfg, err := config.Load(env(tc.kv))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if cfg.RotationFakeAdapters != tc.want {
			t.Errorf("%s: RotationFakeAdapters = %v, want %v", tc.name, cfg.RotationFakeAdapters, tc.want)
		}
	}
}

// The worker's /metrics listener (issue #302) is off by default and refuses a
// public bind unless it is explicitly allowed, in prod and elsewhere.
func TestWorkerMetricsAddr(t *testing.T) {
	prod := func(kv ...string) map[string]string { return with(safeProd(), kv...) }
	dev := func(kv ...string) map[string]string { return with(map[string]string{"TESSERA_ENV": "dev"}, kv...) }
	for _, e := range []map[string]string{prod(), dev()} {
		if c, err := config.Load(env(e)); err != nil || c.WorkerMetricsAddr != "" {
			t.Errorf("default: %q, %v (want off)", c.WorkerMetricsAddr, err)
		}
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		ok   bool
		addr string
	}{
		{"prod loopback", prod("TESSERA_WORKER_METRICS_ADDR", "127.0.0.1:9465"), true, "127.0.0.1:9465"},
		{"prod private", prod("TESSERA_WORKER_METRICS_ADDR", "10.1.2.3:9465"), true, "10.1.2.3:9465"},
		{"prod link-local v6", prod("TESSERA_WORKER_METRICS_ADDR", "[fe80::1]:9465"), true, "[fe80::1]:9465"},
		{"prod off", prod("TESSERA_WORKER_METRICS_ADDR", "off"), true, ""},
		{"prod public ip", prod("TESSERA_WORKER_METRICS_ADDR", "203.0.113.9:9465"), false, ""},
		{"prod wildcard", prod("TESSERA_WORKER_METRICS_ADDR", "0.0.0.0:9465"), false, ""},
		{"prod bare port", prod("TESSERA_WORKER_METRICS_ADDR", ":9465"), false, ""},
		{"prod v6 wildcard", prod("TESSERA_WORKER_METRICS_ADDR", "[::]:9465"), false, ""},
		{"prod hostname", prod("TESSERA_WORKER_METRICS_ADDR", "worker.example.com:9465"), false, ""},
		{"prod localhost name", prod("TESSERA_WORKER_METRICS_ADDR", "localhost:9465"), false, ""},
		{"prod public allowed", prod("TESSERA_WORKER_METRICS_ADDR", "203.0.113.9:9465", "TESSERA_WORKER_METRICS_ALLOW_PUBLIC", "true"), true, "203.0.113.9:9465"},
		{"prod wildcard allowed", prod("TESSERA_WORKER_METRICS_ADDR", ":9465", "TESSERA_WORKER_METRICS_ALLOW_PUBLIC", "true"), true, ":9465"},
		{"prod allow flag without address", prod("TESSERA_WORKER_METRICS_ALLOW_PUBLIC", "true"), false, ""},
		{"prod bad port", prod("TESSERA_WORKER_METRICS_ADDR", "10.0.0.1:0"), false, ""},
		{"prod no port", prod("TESSERA_WORKER_METRICS_ADDR", "10.0.0.1"), false, ""},
		{"dev loopback", dev("TESSERA_WORKER_METRICS_ADDR", "127.0.0.1:9465"), true, "127.0.0.1:9465"},
		{"dev wildcard", dev("TESSERA_WORKER_METRICS_ADDR", ":9465"), false, ""},
		{"dev public", dev("TESSERA_WORKER_METRICS_ADDR", "198.51.100.1:9465"), false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := config.Load(env(tc.env))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err == nil && c.WorkerMetricsAddr != tc.addr {
				t.Errorf("addr = %q, want %q", c.WorkerMetricsAddr, tc.addr)
			}
		})
	}
	// the flag of `tessera worker` goes through the same check
	if _, err := config.CheckWorkerMetricsAddr("203.0.113.9:1", false); err == nil {
		t.Error("a public address passed the flag check")
	}
	if a, err := config.CheckWorkerMetricsAddr(" 127.0.0.1:1 ", false); err != nil || a != "127.0.0.1:1" {
		t.Errorf("loopback flag = %q, %v", a, err)
	}
}

func TestObjectStoreURLs(t *testing.T) {
	ok := func(kv ...string) *config.Config {
		t.Helper()
		c, err := config.Load(env(with(safeProd(), kv...)))
		if err != nil {
			t.Fatalf("%v: %v", kv, err)
		}
		return c
	}
	bad := func(want string, kv ...string) {
		t.Helper()
		_, err := config.Load(env(with(safeProd(), kv...)))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: err %v, want %q", kv, err, want)
		}
	}
	// the anchor may sit in any of the three clouds' immutable storage
	for _, a := range []string{"azure://acct123/anchors/tessera", "gs://tessera-anchors/tessera", "s3://anchors/tessera"} {
		ok("TESSERA_AUDIT_ANCHOR", a)
	}
	bad("azure://… or gs://", "TESSERA_AUDIT_ANCHOR", "file:///tmp/a.jsonl")
	bad("TESSERA_AUDIT_ANCHOR", "TESSERA_AUDIT_ANCHOR", "azure://AB/c")
	bad("endpoint option must be https", "TESSERA_AUDIT_ANCHOR", "gs://bkt/p?endpoint=http://minio.example.com")
	bad("TESSERA_AUDIT_ANCHOR", "TESSERA_AUDIT_ANCHOR", "ftp://x/y")

	// archive: workload identity needs no token; a token with a cloud scheme is a mistake
	c := ok("TESSERA_ARCHIVE_URL", "s3://tessera-archive/segments?region=eu-west-1")
	if c.ArchiveURL == "" {
		t.Error("archive url dropped")
	}
	ok("TESSERA_ARCHIVE_URL", "gs://tessera-archive")
	ok("TESSERA_ARCHIVE_URL", "azure://acct123/archive")
	bad("applies to http(s) archive stores only", "TESSERA_ARCHIVE_URL", "gs://tessera-archive", "TESSERA_ARCHIVE_TOKEN_SEALED", "AAAA")
	bad("TESSERA_ARCHIVE_TOKEN_SEALED", "TESSERA_ARCHIVE_URL", "https://store.example.com/a") // http(s) still needs its token in prod

	// backups copied to an object store need the local backup directory
	ok("TESSERA_BACKUP_DIR", "/backups", "TESSERA_BACKUP_URL", "s3://tessera-backups/db")
	bad("needs TESSERA_BACKUP_DIR", "TESSERA_BACKUP_URL", "s3://tessera-backups/db")
	bad("must be an s3://, azure:// or gs://", "TESSERA_BACKUP_DIR", "/backups", "TESSERA_BACKUP_URL", "https://x.example.com/b")
}

// A KEK file owned by someone else is refused even when its mode is fine:
// that user could replace it.
func TestKEKFileOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(path, []byte(testKEK+"\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 12345, -1); err != nil {
		t.Skip("cannot chown (not root, or not unix): ", err)
	}
	if os.Geteuid() == 12345 {
		t.Skip("running as the test uid")
	}
	_, err := config.Load(env(with(safeProd(), "TESSERA_KEK", "<unset>", "TESSERA_KEK_FILE", path)))
	if err == nil || !strings.Contains(err.Error(), "owned by uid 12345") {
		t.Fatalf("a KEK file owned by another user: %v", err)
	}
}

const wrappedKEK = "AQIDBAUGBwgJCgsMDQ4PEA==" // any base64: the ciphertext is opaque to config

func TestWrappedKEK(t *testing.T) {
	kms := "aws:arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	prod := with(safeProd(), "TESSERA_KEK", "<unset>")
	c, err := config.Load(env(with(prod, "TESSERA_KEK_WRAPPED", wrappedKEK, "TESSERA_KEK_KMS", kms)))
	if err != nil {
		t.Fatal(err)
	}
	if !c.KEKWrapped() {
		t.Fatal("not marked wrapped")
	}
	if _, err := c.Sealer(""); err == nil || !strings.Contains(err.Error(), "ResolveKEK") {
		t.Fatalf("Sealer before ResolveKEK (a dev KEK must never be generated): %v", err)
	}
	if strings.Contains(fmt.Sprint(c)+fmt.Sprintf("%+v", c), wrappedKEK) {
		t.Error("the wrapped key is printed")
	}
	good := bytesOf(0x42)
	var gotRef string
	if err := c.ResolveKEK(context.Background(), func(_ context.Context, ref kekwrap.Ref, w []byte) ([]byte, error) {
		gotRef = ref.String()
		return good, nil
	}); err != nil {
		t.Fatal(err)
	}
	if gotRef != kms || c.KEKWrapped() {
		t.Fatalf("ref %q wrapped %v", gotRef, c.KEKWrapped())
	}
	if _, err := c.Sealer(""); err != nil {
		t.Fatalf("Sealer after ResolveKEK: %v", err)
	}
	// ResolveKEK is a no-op for an ordinary KEK and propagates provider errors
	plain, _ := config.Load(env(safeProd()))
	if err := plain.ResolveKEK(context.Background(), func(context.Context, kekwrap.Ref, []byte) ([]byte, error) {
		t.Error("unwrap called for a plain KEK")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	c2, _ := config.Load(env(with(prod, "TESSERA_KEK_WRAPPED", wrappedKEK, "TESSERA_KEK_KMS", kms)))
	if err := c2.ResolveKEK(context.Background(), func(context.Context, kekwrap.Ref, []byte) ([]byte, error) {
		return nil, errors.New("denied")
	}); err == nil {
		t.Fatal("a failed unwrap was ignored")
	}
	if err := c2.ResolveKEK(context.Background(), func(context.Context, kekwrap.Ref, []byte) ([]byte, error) {
		return []byte("short"), nil
	}); err == nil {
		t.Fatal("a short unwrapped key was accepted")
	}
}

func TestWrappedKEKValidation(t *testing.T) {
	kms := "gcp:projects/p/locations/global/keyRings/r/cryptoKeys/k"
	prod := with(safeProd(), "TESSERA_KEK", "<unset>")
	for _, tc := range []struct {
		name string
		kv   []string
		want string
	}{
		{"wrapped without kms", []string{"TESSERA_KEK_WRAPPED", wrappedKEK}, "must be set together"},
		{"kms without wrapped", []string{"TESSERA_KEK_KMS", kms}, "must be set together"},
		{"not base64", []string{"TESSERA_KEK_WRAPPED", "!!!", "TESSERA_KEK_KMS", kms}, "not base64"},
		{"bad provider", []string{"TESSERA_KEK_WRAPPED", wrappedKEK, "TESSERA_KEK_KMS", "vault:x"}, "unknown KMS provider"},
		{"bad arn", []string{"TESSERA_KEK_WRAPPED", wrappedKEK, "TESSERA_KEK_KMS", "aws:arn:aws:s3:::bucket"}, "KMS key or alias ARN"},
		{"azure not a vault", []string{"TESSERA_KEK_WRAPPED", wrappedKEK, "TESSERA_KEK_KMS", "azure:https://evil.example.com/keys/k/v"}, "vault host"},
		{"azure http", []string{"TESSERA_KEK_WRAPPED", wrappedKEK, "TESSERA_KEK_KMS", "azure:http://v.vault.azure.net/keys/k/v"}, "azure:"},
		{"both KEK and wrapped", []string{"TESSERA_KEK", testKEK, "TESSERA_KEK_WRAPPED", wrappedKEK, "TESSERA_KEK_KMS", kms}, "only one of"},
	} {
		_, err := config.Load(env(with(prod, tc.kv...)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	for _, k := range []string{kms, "azure:https://myvault.vault.azure.net/keys/tessera-kek/0123456789abcdef", "azure:https://myvault.vault.azure.net/keys/tessera-kek"} {
		if _, err := config.Load(env(with(prod, "TESSERA_KEK_WRAPPED", wrappedKEK, "TESSERA_KEK_KMS", k))); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	// prod still needs some KEK
	if _, err := config.Load(env(prod)); err == nil || !strings.Contains(err.Error(), "TESSERA_KEK_WRAPPED") {
		t.Errorf("prod without a KEK: %v", err)
	}
}

func bytesOf(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestLoad_ShutdownAndLogFormat(t *testing.T) {
	c, err := config.Load(env(safeProd()))
	if err != nil {
		t.Fatal(err)
	}
	if c.ShutdownGrace != 25*time.Second || c.ShutdownDrainDelay != 0 || c.LogFormat != "json" {
		t.Errorf("prod defaults: grace %s delay %s format %s", c.ShutdownGrace, c.ShutdownDrainDelay, c.LogFormat)
	}
	dev, err := config.Load(env(map[string]string{"TESSERA_ENV": "dev"}))
	if err != nil || dev.LogFormat != "text" {
		t.Errorf("dev log format: %v %v", dev, err)
	}
	for _, tc := range []struct {
		k, v  string
		ok    bool
		grace time.Duration
	}{
		{"TESSERA_SHUTDOWN_GRACE", "40s", true, 40 * time.Second},
		{"TESSERA_SHUTDOWN_GRACE", "30", true, 30 * time.Second},
		{"TESSERA_SHUTDOWN_GRACE", "0s", false, 0},
		{"TESSERA_SHUTDOWN_GRACE", "11m", false, 0},
		{"TESSERA_SHUTDOWN_GRACE", "soon", false, 0},
		{"TESSERA_SHUTDOWN_DRAIN_DELAY", "3m", false, 0},
		{"TESSERA_LOG_FORMAT", "xml", false, 0},
	} {
		got, err := config.Load(env(with(safeProd(), tc.k, tc.v)))
		if (err == nil) != tc.ok {
			t.Errorf("%s=%s: err %v, want ok=%v", tc.k, tc.v, err, tc.ok)
		}
		if tc.ok && got.ShutdownGrace != tc.grace {
			t.Errorf("%s=%s: grace %s", tc.k, tc.v, got.ShutdownGrace)
		}
	}
}

// TestClientRate: the default token bucket of machine clients (issue #587).
func TestClientRate(t *testing.T) {
	dev := map[string]string{"TESSERA_ENV": "dev"}
	c, err := config.Load(env(dev))
	if err != nil || c.ClientRateBurst != 120 || c.ClientRatePerMinute != 600 {
		t.Fatalf("default = %d/%d, %v; want 120/600", c.ClientRateBurst, c.ClientRatePerMinute, err)
	}
	c, err = config.Load(env(with(dev, "TESSERA_API_CLIENT_RATE_BURST", "10", "TESSERA_API_CLIENT_RATE_PER_MINUTE", "0")))
	if err != nil || c.ClientRateBurst != 10 || c.ClientRatePerMinute != 0 {
		t.Errorf("set = %d/%d, %v; want 10/0 (off)", c.ClientRateBurst, c.ClientRatePerMinute, err)
	}
	for k, bad := range map[string][]string{"TESSERA_API_CLIENT_RATE_BURST": {"0", "-1", "many", "100001"},
		"TESSERA_API_CLIENT_RATE_PER_MINUTE": {"-1", "fast", "600001"}} {
		for _, v := range bad {
			if _, err := config.Load(env(with(dev, k, v))); err == nil {
				t.Errorf("%s=%q was accepted", k, v)
			}
		}
	}
}

// TestClientRateOffInProd: turning the limit off in production is allowed only with the explicit override.
func TestClientRateOffInProd(t *testing.T) {
	c, err := config.Load(env(with(safeProd(), "TESSERA_API_CLIENT_RATE_PER_MINUTE", "0", "TESSERA_API_CLIENT_RATE_ALLOW_OFF", "true")))
	if err != nil || c.ClientRatePerMinute != 0 {
		t.Errorf("with the override: %v, %v", c.ClientRatePerMinute, err)
	}
	if _, err := config.Load(env(with(safeProd(), "TESSERA_API_CLIENT_RATE_ALLOW_OFF", "true"))); err != nil {
		t.Errorf("override alone: %v", err)
	}
}
