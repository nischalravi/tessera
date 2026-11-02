package readiness

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestValidateConn_GoogleOrgUnits: base_dns on a Google Workspace connection is
// a list of org unit paths (issue #594): optional, well formed, bounded; the
// message never echoes the input.
func TestValidateConn_GoogleOrgUnits(t *testing.T) {
	ok := ConnConfig{Customer: "my_customer"}
	many := make([]string, 51)
	for i := range many {
		many[i] = fmt.Sprintf("/ou%d", i)
	}
	for name, tc := range map[string]struct {
		ous  []string
		good bool
	}{
		"none":                {nil, true},
		"root":                {[]string{"/"}, true},
		"nested with a space": {[]string{"/Eng", "/Sales/EMEA West"}, true},
		"fifty":               {many[:50], true},
		"fifty one":           {many, false},
		"no leading slash":    {[]string{"Eng"}, false},
		"a DN":                {[]string{"OU=People,DC=example,DC=com"}, false},
		"empty":               {[]string{""}, false},
		"trailing slash":      {[]string{"/Eng/"}, false},
		"empty segment":       {[]string{"/Eng//Ops"}, false},
		"quote":               {[]string{"/Eng' OR 1=1"}, false},
		"backslash":           {[]string{`/Eng\x`}, false},
		"control character":   {[]string{"/Eng\nX"}, false},
		"too long":            {[]string{"/" + strings.Repeat("a", 256)}, false},
		"duplicate":           {[]string{"/Eng", "/Eng"}, false},
	} {
		cfg := ok
		cfg.BaseDNs = tc.ous
		var bad []FieldError
		for _, fe := range ValidateConnEnv(cfg, tmplOfID(t, "google"), "google", config.Prod) {
			if fe.Field == "base_dns" {
				bad = append(bad, fe)
				for _, in := range tc.ous {
					if len(in) > 3 && strings.Contains(fe.Msg, in) {
						t.Errorf("%s: message echoes the input: %q", name, fe.Msg)
					}
				}
			}
		}
		if (len(bad) == 0) != tc.good {
			t.Errorf("%s: base_dns errors = %v, want good=%v", name, bad, tc.good)
		}
	}
}

// TestValidateConn_GoogleAdminEmail: admin_email is the administrator to impersonate (issue
// #818): optional in the config, a well-formed address, in the connection's domain when one is
// set; the message never echoes the input.
func TestValidateConn_GoogleAdminEmail(t *testing.T) {
	for name, tc := range map[string]struct {
		domain, email string
		good          bool
	}{
		"none":                 {"example.com", "", true},
		"in the domain":        {"example.com", "admin@example.com", true},
		"domain case":          {"Example.com", "admin@EXAMPLE.com", true},
		"no domain set":        {"", "admin@example.org", true},
		"other domain":         {"example.com", "admin@evil.example.org", false},
		"subdomain":            {"example.com", "admin@sub.example.com", false},
		"no at":                {"", "admin", false},
		"no local part":        {"", "@example.com", false},
		"no domain part":       {"", "admin@", false},
		"space":                {"", "ad min@example.com", false},
		"two addresses":        {"", "a@example.com,b@example.com", false},
		"display name":         {"", "Admin <admin@example.com>", false},
		"control character":    {"", "admin@example.com\n", false},
		"too long":             {"", strings.Repeat("a", 250) + "@example.com", false},
		"ip literal":           {"", "admin@[10.0.0.1]", false},
		"domain mismatch only": {"example.com", "admin@example.co", false},
	} {
		cfg := ConnConfig{Customer: "my_customer", Domain: tc.domain, AdminEmail: tc.email}
		var bad []FieldError
		for _, fe := range ValidateConnEnv(cfg, tmplOfID(t, "google"), "google", config.Prod) {
			if fe.Field == "admin_email" {
				bad = append(bad, fe)
				if tc.email != "" && strings.Contains(fe.Msg, tc.email) || tc.domain != "" && strings.Contains(fe.Msg, tc.domain) {
					t.Errorf("%s: message echoes the input: %q", name, fe.Msg)
				}
			}
		}
		if (len(bad) == 0) != tc.good {
			t.Errorf("%s: admin_email errors = %v, want good=%v", name, bad, tc.good)
		}
	}
}

// A live Google Workspace connection's connector is opened from its stored config
// (issue #814): its org units (base_dns), customer and domain reach the builder with
// the opened credential, for the sync and for OpenConnector; a dry run opens it too.
func TestGoogleConnectorIsOpenedFromTheStoredConfig(t *testing.T) {
	govConfig["google"] = `{"customer":"my_customer","domain":"example.com","admin_email":"admin@example.com","correlation_key":"id","base_dns":["/Eng","/Sales/EMEA"]}`
	t.Cleanup(func() { delete(govConfig, "google") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	var built []governed.Params
	s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
		built = append(built, p)
		return fakeConnector{"google"}, nil
	}
	st := newStore(t)
	activateGov(t, s, st, "google")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(failed) != 0 || len(cns) != 1 || cns[0].System() != "google" {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	if len(built) != 1 {
		t.Fatalf("connector built %d times", len(built))
	}
	p := built[0]
	if p.Type != governed.GoogleWorkspace || p.Customer != "my_customer" || p.Domain != "example.com" || p.AdminEmail != "admin@example.com" || p.Secret != govSecret ||
		!slices.Equal(p.OrgUnits, []string{"/Eng", "/Sales/EMEA"}) {
		t.Errorf("opened with %+v", p)
	}
	read(t, st, func(c *store.TenantTx) error {
		live, err := s.ActiveConnections(c)
		if err != nil || len(live) != 1 {
			t.Fatalf("active connections: %v, %v", live, err)
		}
		if cn, ok, err := s.OpenConnector(c, live[0], t0); err != nil || !ok || cn == nil {
			t.Errorf("OpenConnector: ok %v, err %v", ok, err)
		}
		return nil
	})
}

// A live Google connection that cannot be opened is returned as a NotOpenedError for
// its system, so a sync drops the env-configured google connector instead of letting
// it read a wider scope (issue #823); StoredSystems names the system either way.
func TestGoogleConnectionThatDoesNotOpenFailsClosed(t *testing.T) {
	govConfig["google"] = `{"customer":"my_customer","domain":"example.com","admin_email":"admin@example.com","correlation_key":"id","base_dns":["/Eng"]}`
	t.Cleanup(func() { delete(govConfig, "google") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	s.Runner.Gov.Connector = func(governed.Params, governed.Net) (connectors.Connector, error) {
		return nil, errors.New("google: no admin_email")
	}
	st := newStore(t)
	activateGov(t, s, st, "google")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(cns) != 0 || len(failed) != 1 {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	for name, e := range failed {
		var no *connectors.NotOpenedError
		if !errors.As(e, &no) || no.System != "google" {
			t.Errorf("%s: failure %v does not name the google system", name, e)
		}
	}
	read(t, st, func(c *store.TenantTx) error {
		got, err := s.StoredSystems(c)
		if err != nil || !slices.Equal(got, []string{"google"}) {
			t.Errorf("stored systems = %v, %v", got, err)
		}
		return nil
	})
}
