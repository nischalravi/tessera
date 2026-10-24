package readiness

import (
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/successfactors"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
)

// The template's host allowlist and the connector's are one list: the
// readiness form must not accept a host the connector would refuse, or the
// reverse.
func TestSuccessFactorsAllowlistsAgree(t *testing.T) {
	r, ok := template.MustDefault().Get("successfactors")
	if !ok {
		t.Fatal("no successfactors template")
	}
	if !slices.Equal(r.HostAllowlist, successfactors.HostAllowlist) {
		t.Errorf("template %v, connector %v", r.HostAllowlist, successfactors.HostAllowlist)
	}
	if r.Role != "authoritative" {
		t.Errorf("role %q: an HR source is authoritative", r.Role)
	}
}

func TestSuccessFactorsConfigValidation(t *testing.T) {
	r, _ := template.MustDefault().Get("successfactors")
	good := ConnConfig{CorrelationKey: "person_id", BaseURL: "https://api4.successfactors.com", WriteMode: "off",
		Settings: map[string]string{"company_id": "acme", "username": "tessera-api"}}
	fields := func(cfg ConnConfig) []string {
		var out []string
		for _, e := range ValidateConn(cfg, r, "successfactors") {
			out = append(out, e.Field)
		}
		return out
	}
	if got := fields(good); len(got) != 0 {
		t.Fatalf("good config: %v", got)
	}
	for name, tc := range map[string]struct {
		mut  func(*ConnConfig)
		want string
	}{
		"look-alike host":    {func(c *ConnConfig) { c.BaseURL = "https://successfactors.com.evil.example" }, "base_url"},
		"foreign host":       {func(c *ConnConfig) { c.BaseURL = "https://evil.example" }, "base_url"},
		"apex":               {func(c *ConnConfig) { c.BaseURL = "https://successfactors.com" }, "base_url"},
		"plain http":         {func(c *ConnConfig) { c.BaseURL = "http://api4.successfactors.com" }, "base_url"},
		"a port":             {func(c *ConnConfig) { c.BaseURL = "https://api4.successfactors.com:8443" }, "base_url"},
		"loopback":           {func(c *ConnConfig) { c.BaseURL = "https://127.0.0.1" }, "base_url"},
		"a path":             {func(c *ConnConfig) { c.BaseURL = "https://api4.successfactors.com/odata/v2" }, "base_url"},
		"no base url":        {func(c *ConnConfig) { c.BaseURL = "" }, "base_url"},
		"no company":         {func(c *ConnConfig) { c.Settings = map[string]string{"username": "u"} }, "settings.company_id"},
		"write-back":         {func(c *ConnConfig) { c.WriteMode = "scoped" }, "write_mode"},
		"dry-run write-back": {func(c *ConnConfig) { c.WriteMode = "dry_run" }, "write_mode"},
		"foreign setting":    {func(c *ConnConfig) { c.Settings["org"] = "x" }, "settings.org"},
	} {
		cfg := good
		cfg.Settings = map[string]string{"company_id": "acme", "username": "tessera-api"}
		tc.mut(&cfg)
		if got := fields(cfg); !slices.Contains(got, tc.want) {
			t.Errorf("%s: want an error on %s, got %v", name, tc.want, got)
		}
	}
	for _, host := range []string{"https://api4.successfactors.com", "https://api55.sapsf.eu", "https://api10.sapsf.cn", "https://x.successfactors.eu", "https://x.sapsf.com"} {
		cfg := good
		cfg.BaseURL = host
		if got := fields(cfg); len(got) != 0 {
			t.Errorf("%s: %v", host, got)
		}
	}
}
