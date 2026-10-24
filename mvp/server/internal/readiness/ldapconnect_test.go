package readiness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestValidateLDAPConnect covers the connect-form rules of issue #585: the
// host is a host name, any directory port is allowed, tls_mode none is dev
// only, and the page size and attribute map are bounded.
func TestValidateLDAPConnect(t *testing.T) {
	tmpl := ldapTmpl(t)
	base := ConnConfig{Host: "ldapd.neu.edu", Port: 3890, BaseDNs: []string{"dc=x"}, CorrelationKey: "entryUUID"}
	for name, tc := range map[string]struct {
		mut   func(*ConnConfig)
		env   string
		field string // "" means no error expected
	}{
		"custom port":        {func(c *ConnConfig) {}, config.Prod, ""},
		"ldaps on 6360":      {func(c *ConnConfig) { c.Port = 6360; c.TLSMode = "ldaps" }, config.Prod, ""},
		"connection name":    {func(c *ConnConfig) { c.Host = "Zed Directory" }, config.Prod, "host"},
		"scheme":             {func(c *ConnConfig) { c.Host = "ldaps://zed.test" }, config.Prod, "host"},
		"host with port":     {func(c *ConnConfig) { c.Host = "zed.test:636" }, config.Prod, "host"},
		"host with path":     {func(c *ConnConfig) { c.Host = "zed.test/x" }, config.Prod, "host"},
		"empty host":         {func(c *ConnConfig) { c.Host = "" }, config.Prod, "host"},
		"ip host":            {func(c *ConnConfig) { c.Host = "192.168.1.10" }, config.Prod, ""},
		"port zero":          {func(c *ConnConfig) { c.Port = 0 }, config.Prod, "port"},
		"port too high":      {func(c *ConnConfig) { c.Port = 70000 }, config.Prod, "port"},
		"ssh port":           {func(c *ConnConfig) { c.Port = 22 }, config.Prod, "port"},
		"database port":      {func(c *ConnConfig) { c.Port = 3306 }, config.Prod, "port"},
		"unknown tls mode":   {func(c *ConnConfig) { c.TLSMode = "ssl" }, config.Prod, "tls_mode"},
		"none in prod":       {func(c *ConnConfig) { c.TLSMode = "none" }, config.Prod, "tls_mode"},
		"none in dev":        {func(c *ConnConfig) { c.TLSMode = "none" }, config.Dev, ""},
		"page size":          {func(c *ConnConfig) { c.PageSize = 1000 }, config.Prod, ""},
		"page size too big":  {func(c *ConnConfig) { c.PageSize = MaxPageSize + 1 }, config.Prod, "page_size"},
		"negative page size": {func(c *ConnConfig) { c.PageSize = -1 }, config.Prod, "page_size"},
		"attr map":           {func(c *ConnConfig) { c.AttrMap = []AttrMapping{{"department", "dept", "identity"}} }, config.Prod, ""},
		"attr map bad name":  {func(c *ConnConfig) { c.AttrMap = []AttrMapping{{"a b", "dept", "identity"}} }, config.Prod, "attr_map"},
		"attr map bad scope": {func(c *ConnConfig) { c.AttrMap = []AttrMapping{{"department", "dept", "group"}} }, config.Prod, "attr_map"},
		"attr map target twice": {func(c *ConnConfig) {
			c.AttrMap = []AttrMapping{{"department", "dept", "account"}, {"ou", "Dept", "account"}}
		}, config.Prod, "attr_map"},
	} {
		cfg := base
		tc.mut(&cfg)
		var got []string
		for _, fe := range ValidateConnEnv(cfg, tmpl, "ldap", tc.env) {
			got = append(got, fe.Field)
			if strings.Contains(fe.Msg, cfg.Host) && cfg.Host != "" {
				t.Errorf("%s: message echoes the input: %q", name, fe.Msg)
			}
		}
		switch {
		case tc.field == "" && len(got) > 0:
			t.Errorf("%s: unexpected errors on %v", name, got)
		case tc.field != "" && !slices_contains(got, tc.field):
			t.Errorf("%s: no error on %s (got %v)", name, tc.field, got)
		}
	}
}

func slices_contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestTLSModeOf(t *testing.T) {
	for _, tc := range []struct {
		cfg  ConnConfig
		want string
	}{
		{ConnConfig{Port: 636}, "ldaps"}, {ConnConfig{Port: 389}, "starttls"}, {ConnConfig{Port: 3890}, "starttls"},
		{ConnConfig{Port: 6360, TLSMode: "ldaps"}, "ldaps"}, {ConnConfig{Port: 3890, TLSMode: "none"}, "none"},
	} {
		if got := TLSModeOf(tc.cfg); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.cfg, got, tc.want)
		}
	}
}

// TestSetCredential_DNInReference: a bind DN typed into the reference field
// gets a message that names the right fields, and never echoes the input.
func TestSetCredential_DNInReference(t *testing.T) {
	st, s, _, _ := agentSvc(t)
	id := newLDAP(t, s, st)
	dn := "uid=svc-secret-dn,ou=people,dc=example,dc=com"
	err := st.Write(context.Background(), func(c *store.TenantTx) error {
		_, err := s.SetCredential(c, id, CredentialInput{Reference: dn}, "admin", t0)
		return err
	})
	var re *Error
	if !errors.As(err, &re) || re.Code != "invalid_credential" {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"Bind DN", "Or the secret"} {
		if !strings.Contains(re.Msg, want) {
			t.Errorf("message %q lacks %q", re.Msg, want)
		}
	}
	if strings.Contains(re.Msg, "svc-secret-dn") {
		t.Error("message echoes the input")
	}
}
