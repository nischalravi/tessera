package readiness

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A live ServiceNow, Atlassian or SuccessFactors connection's connector is opened from its stored
// config (issue #814): its base_url and settings reach the builder with the opened credential, and
// a connection that does not open fails closed, naming its system, so the env-configured connector
// is not read in its place.
func TestSnowAtlassianSuccessFactorsAreOpenedFromTheStoredConfig(t *testing.T) {
	for _, tc := range []struct {
		typ, base, setting, want string
	}{
		{"servicenow", "https://acme.service-now.com", "username", "tessera.integration"},
		{"atlassian", "https://acme.atlassian.net", "email", "tessera@acme.example"},
		{"successfactors", "https://api4.successfactors.com", "company_id", "acme"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			var opened []governed.Params
			s := govSvc(t, &opened, stubProber{})
			passingEvidence(s, t0.Add(48*time.Hour))
			var built []governed.Params
			s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
				built = append(built, p)
				return fakeConnector{tc.typ}, nil
			}
			st := newStore(t)
			activateGov(t, s, st, tc.typ)
			cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
			if err != nil || len(failed) != 0 || len(cns) != 1 || cns[0].System() != tc.typ {
				t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
			}
			if len(built) != 1 {
				t.Fatalf("connector built %d times", len(built))
			}
			if p := built[0]; p.Type != tc.typ || p.BaseURL != tc.base || p.Settings[tc.setting] != tc.want || p.Secret != govSecret {
				t.Errorf("opened with %+v", p)
			}
			read(t, st, func(c *store.TenantTx) error {
				got, err := s.StoredSystems(c)
				if err != nil || !slices.Equal(got, []string{tc.typ}) {
					t.Errorf("stored systems = %v, %v", got, err)
				}
				return nil
			})

			s.Runner.Gov.Connector = func(governed.Params, governed.Net) (connectors.Connector, error) {
				return nil, errors.New(tc.typ + ": bad credential")
			}
			cns, failed, err = s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
			if err != nil || len(cns) != 0 || len(failed) != 1 {
				t.Fatalf("after a failure: %v, failed %v, %v", cns, failed, err)
			}
			for name, e := range failed {
				var no *connectors.NotOpenedError
				if !errors.As(e, &no) || no.System != tc.typ {
					t.Errorf("%s: failure %v does not name the %s system", name, e, tc.typ)
				}
			}
		})
	}
}

// The instance URL of each is refused on save unless it is on the vendor's domain over https.
func TestSnowAtlassianSuccessFactorsConfigRefusesOtherHosts(t *testing.T) {
	for _, tc := range []struct {
		typ, name, cfg string
		bad            bool
	}{
		{"servicenow", "ok", `{"correlation_key":"id","base_url":"https://acme.service-now.com","settings":{"username":"u"}}`, false},
		{"servicenow", "gov cloud", `{"correlation_key":"id","base_url":"https://acme.servicenowservices.com","settings":{"username":"u"}}`, false},
		{"servicenow", "other host", `{"correlation_key":"id","base_url":"https://evil.example.com","settings":{"username":"u"}}`, true},
		{"servicenow", "look-alike", `{"correlation_key":"id","base_url":"https://service-now.com.evil.example","settings":{"username":"u"}}`, true},
		{"servicenow", "metadata", `{"correlation_key":"id","base_url":"https://169.254.169.254","settings":{"username":"u"}}`, true},
		{"servicenow", "http", `{"correlation_key":"id","base_url":"http://acme.service-now.com","settings":{"username":"u"}}`, true},
		{"atlassian", "ok", `{"correlation_key":"id","base_url":"https://acme.atlassian.net","settings":{"email":"a@acme.example"}}`, false},
		{"atlassian", "other host", `{"correlation_key":"id","base_url":"https://evil.example.com","settings":{"email":"a@acme.example"}}`, true},
		{"atlassian", "api host", `{"correlation_key":"id","base_url":"https://api.atlassian.com","settings":{"email":"a@acme.example"}}`, true},
		{"atlassian", "metadata", `{"correlation_key":"id","base_url":"https://169.254.169.254","settings":{"email":"a@acme.example"}}`, true},
		{"atlassian", "http", `{"correlation_key":"id","base_url":"http://acme.atlassian.net","settings":{"email":"a@acme.example"}}`, true},
		{"successfactors", "ok", `{"base_url":"https://api4.successfactors.com","correlation_key":"person_id","settings":{"company_id":"acme","username":"u"}}`, false},
		{"successfactors", "other host", `{"base_url":"https://evil.example.com","correlation_key":"person_id","settings":{"company_id":"acme","username":"u"}}`, true},
		{"successfactors", "metadata", `{"base_url":"https://169.254.169.254","correlation_key":"person_id","settings":{"company_id":"acme","username":"u"}}`, true},
		{"successfactors", "http", `{"base_url":"http://api4.successfactors.com","correlation_key":"person_id","settings":{"company_id":"acme","username":"u"}}`, true},
	} {
		t.Run(tc.typ+" "+tc.name, func(t *testing.T) {
			r, ok := template.MustDefault().Get(tc.typ)
			if !ok {
				t.Fatal("no template")
			}
			cfg, err := DecodeConfig([]byte(tc.cfg))
			if err != nil {
				t.Fatal(err)
			}
			errs := ValidateConnEnv(cfg, r, tc.typ, "prod")
			var onURL bool
			for _, fe := range errs {
				onURL = onURL || fe.Field == "base_url"
			}
			if onURL != tc.bad || (!tc.bad && len(errs) != 0) {
				t.Errorf("errors %v, want a base_url error: %v", errs, tc.bad)
			}
		})
	}
}
