package readiness

import (
	"context"
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

// A live Google Workspace connection's connector is opened from its stored config
// (issue #814): its org units (base_dns), customer and domain reach the builder with
// the opened credential, for the sync and for OpenConnector; a dry run opens it too.
func TestGoogleConnectorIsOpenedFromTheStoredConfig(t *testing.T) {
	govConfig["google"] = `{"customer":"my_customer","domain":"example.com","correlation_key":"id","base_dns":["/Eng","/Sales/EMEA"]}`
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
	if p.Type != governed.GoogleWorkspace || p.Customer != "my_customer" || p.Domain != "example.com" || p.Secret != govSecret ||
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
