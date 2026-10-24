package sqldb

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

var (
	prodRT = connsync.Runtime{Env: config.Prod}
	devRT  = connsync.Runtime{Env: config.Dev, AllowLoopback: true}
)

func goodConfig(engine string) Config {
	return Config{Engine: engine, Host: "db.example.com", Database: "app", Username: "tessera_ro", Mode: ModeNative}
}

func TestConfig_Validate(t *testing.T) {
	app := &App{AccountsQuery: "SELECT id FROM users"}
	tests := []struct {
		name string
		edit func(c *Config)
		rt   connsync.Runtime
		want string // empty: valid
	}{
		{"valid", func(*Config) {}, prodRT, ""},
		{"ip host", func(c *Config) { c.Host = "203.0.113.9" }, prodRT, ""},
		{"app mode", func(c *Config) { c.Mode, c.App = ModeApp, app }, prodRT, ""},
		{"bad engine", func(c *Config) { c.Engine = "db2" }, prodRT, "engine must be"},
		{"scheme in host", func(c *Config) { c.Host = "postgres://db" }, prodRT, "host must be"},
		{"port in host", func(c *Config) { c.Host = "db:5432" }, prodRT, "host must be"},
		{"path in host", func(c *Config) { c.Host = "db/x" }, prodRT, "host must be"},
		{"empty host", func(c *Config) { c.Host = "" }, prodRT, "host must be"},
		{"port range", func(c *Config) { c.Port = 70000 }, prodRT, "port must be"},
		{"no username", func(c *Config) { c.Username = "" }, prodRT, "username is required"},
		{"control in username", func(c *Config) { c.Username = "a\nb" }, prodRT, "username is required"},
		{"database with space", func(c *Config) { c.Database = "a b" }, prodRT, "database is not"},
		{"tls disable in prod", func(c *Config) { c.TLS = TLSDisable }, prodRT, "dev only"},
		{"tls disable in dev", func(c *Config) { c.TLS = TLSDisable }, devRT, ""},
		{"tls unknown", func(c *Config) { c.TLS = "prefer" }, prodRT, "tls must be"},
		{"private key in ca", func(c *Config) { c.CABundle = "-----BEGIN PRIVATE KEY-----" }, prodRT, "certificates only"},
		{"junk ca", func(c *Config) { c.CABundle = "not pem" }, prodRT, "no PEM certificate"},
		{"timeout", func(c *Config) { c.QueryTimeoutSeconds = 3600 }, prodRT, "query_timeout_seconds"},
		{"rows", func(c *Config) { c.MaxRows = MaxRowsLimit + 1 }, prodRT, "max_rows"},
		{"bad mode", func(c *Config) { c.Mode = "x" }, prodRT, "mode must be"},
		{"app without statements", func(c *Config) { c.Mode = ModeApp }, prodRT, "needs app statements"},
		{"app in native", func(c *Config) { c.App = app }, prodRT, "app applies to mode"},
		{"app bad statement", func(c *Config) { c.Mode, c.App = ModeApp, &App{AccountsQuery: "DELETE FROM users"} }, prodRT, "app.accounts_query"},
		{"app write placeholder", func(c *Config) {
			c.Mode, c.App = ModeApp, &App{AccountsQuery: "SELECT id FROM u", CreateAccount: "INSERT INTO u (n) VALUES (:nope)"}
		}, prodRT, "unknown placeholder :nope"},
		{"bad system", func(c *Config) { c.System = "Has Space" }, prodRT, "system must be"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := goodConfig(Postgres)
			tt.edit(&c)
			err := c.Validate(tt.rt)
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Fatalf("err = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestConfig_Defaults(t *testing.T) {
	for engine, port := range map[string]int{Postgres: 5432, MySQL: 3306, SQLServer: 1433, Oracle: 1521} {
		c := goodConfig(engine)
		if c.EffectivePort() != port || DefaultPort(engine) != port {
			t.Errorf("%s: port %d", engine, c.EffectivePort())
		}
	}
	c := goodConfig(Postgres)
	c.Port = 6543
	if c.EffectivePort() != 6543 || c.timeout() != DefaultQueryTimeout || c.maxRows() != DefaultMaxRows || c.SystemName() != "sql" {
		t.Errorf("defaults: %d %v %d %s", c.EffectivePort(), c.timeout(), c.maxRows(), c.SystemName())
	}
}

func TestDecodeApp_Strict(t *testing.T) {
	if _, err := DecodeApp([]byte(`{"accounts_query":"SELECT id FROM u"}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"accounts_query":"SELECT 1","password":"x"}`, `{"accounts_query":1}`, `{} {}`, `nope`} {
		if _, err := DecodeApp([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestTLSConfig(t *testing.T) {
	c := goodConfig(Postgres)
	tc, err := tlsConfig(c)
	if err != nil || tc == nil {
		t.Fatalf("%v %v", tc, err)
	}
	if tc.MinVersion != tls.VersionTLS12 || tc.ServerName != "db.example.com" || tc.InsecureSkipVerify {
		t.Errorf("tls config = %+v", tc)
	}
	c.TLS = TLSDisable
	if tc, _ := tlsConfig(c); tc != nil {
		t.Error("tls disable still produced a config")
	}
	c.TLS, c.CABundle = "", "garbage"
	if _, err := tlsConfig(c); err == nil {
		t.Error("a bad CA bundle was accepted")
	}
}

// Production dials through the SSRF policy: loopback, private, link-local and
// metadata addresses are refused for every engine, before any byte is sent.
func TestOpen_RefusesBlockedAddresses(t *testing.T) {
	hosts := []string{"127.0.0.1", "10.1.2.3", "192.168.0.5", "169.254.169.254", "100.100.100.200", "::1", "fd00:ec2::254"}
	for _, engine := range Engines {
		for _, host := range hosts {
			c := goodConfig(engine)
			c.Host = host
			db, err := Open(c, connsync.NewSecret("pw"), prodRT, false)
			if err != nil {
				t.Fatalf("%s %s: %v", engine, host, err)
			}
			err = db.PingContext(context.Background())
			_ = db.Close()
			if err == nil || !blocked(err) {
				t.Errorf("%s %s: err = %v, want the address refused", engine, host, err)
			}
		}
	}
}

func blocked(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "not allowed") || strings.Contains(m, "blocked") || strings.Contains(m, "destination address")
}

// The metadata address stays refused in dev, even with the loopback exception.
func TestOpen_DevStillRefusesMetadata(t *testing.T) {
	c := goodConfig(Postgres)
	c.Host, c.TLS = "169.254.169.254", TLSDisable
	db, err := Open(c, connsync.NewSecret("pw"), devRT, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err == nil || !blocked(err) {
		t.Fatalf("err = %v, want the address refused", err)
	}
}

func TestOpen_Refuses(t *testing.T) {
	c := goodConfig(Postgres)
	if _, err := Open(c, connsync.Secret{}, prodRT, false); err == nil {
		t.Error("an empty password was accepted")
	}
	c.TLS = TLSDisable
	if _, err := Open(c, connsync.NewSecret("pw"), prodRT, false); err == nil {
		t.Error("tls disable was accepted in prod")
	}
}

// Errors never carry the password.
func TestScrub(t *testing.T) {
	pw := connsync.NewSecret("hunter2-secret")
	err := scrub(errors.New("dial db: login failed for password hunter2-secret"), pw)
	if strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "REDACTED") {
		t.Errorf("scrub = %v", err)
	}
	if scrub(nil, pw) != nil {
		t.Error("nil error changed")
	}
}

func TestSecretNeverPrints(t *testing.T) {
	pw := connsync.NewSecret("hunter2-secret")
	for _, s := range []string{pw.String()} {
		if strings.Contains(s, "hunter2") {
			t.Fatal("secret printed")
		}
	}
}
