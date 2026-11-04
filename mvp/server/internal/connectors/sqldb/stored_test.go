package sqldb

import (
	"strings"
	"testing"
)

// FromStored validates the stored settings under the runtime's policy and needs the password; it
// reads nothing from the environment.
func TestFromStored(t *testing.T) {
	t.Setenv("TESSERA_SQL_HOST", "env.example.com")
	cfg := goodConfig("postgres")
	cn, err := FromStored(&cfg, "pw", prodRT)
	if err != nil {
		t.Fatal(err)
	}
	if cn.System() != "sql" {
		t.Errorf("system %q", cn.System())
	}
	cfg.Mode = "" // defaults to native
	if _, err := FromStored(&cfg, "pw", prodRT); err != nil {
		t.Errorf("empty mode: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Config)
		pw   string
		want string
	}{
		{"no password", func(*Config) {}, "", "no stored credential"},
		{"metadata host", func(c *Config) { c.Host = "169.254.169.254" }, "SECRET-VALUE", "metadata"},
		{"tls disabled in prod", func(c *Config) { c.TLS = "disable" }, "SECRET-VALUE", "tls"},
		{"bad engine", func(c *Config) { c.Engine = "db2" }, "SECRET-VALUE", "engine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := goodConfig("postgres")
			tc.edit(&c)
			_, err := FromStored(&c, tc.pw, prodRT)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "SECRET-VALUE") {
				t.Errorf("error %v, want one containing %q and no secret", err, tc.want)
			}
		})
	}
	if _, err := FromStored(nil, "pw", prodRT); err == nil {
		t.Error("nil settings opened")
	}
}
