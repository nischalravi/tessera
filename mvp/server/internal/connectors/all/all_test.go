package all_test

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/all"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// register registers the production connectors with a production-rules
// safehttp test client, the way cmd/tessera does with safehttp.ForConfig.
func register(t *testing.T) {
	t.Helper()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	all.Register(hc, connsync.Runtime{Env: "prod"})
}

var now = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

func TestLoadRegistersTheProductionConnectors(t *testing.T) {
	register(t)
	for _, name := range []string{"okta", "entra", "google", "workday", "github-scan", "aws-agentcore", "cyberark", "delinea", "beyondtrust", "sap", "oracle"} {
		if _, ok := connectors.Factories[name]; !ok {
			t.Errorf("connector %q is not registered", name)
		}
	}
}

func TestDefaultStaysTheDemoCompany(t *testing.T) {
	register(t)
	t.Setenv("TESSERA_CONNECTORS", "")
	conns, err := connectors.Load("", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 5 {
		t.Fatalf("default connectors = %d, want the 5 demo connectors", len(conns))
	}
	for _, c := range conns {
		if !strings.HasPrefix(c.TypeName(), "Demo") {
			t.Errorf("default connector %s is %s, not a demo connector", c.System(), c.TypeName())
		}
	}
}

func TestLoadBuildsTheProductionConnectorsFromTheEnvironment(t *testing.T) {
	register(t)
	t.Setenv("TESSERA_ENV", "prod")
	t.Setenv("TESSERA_OKTA_ORG_URL", "https://example.okta.com")
	t.Setenv("TESSERA_OKTA_API_TOKEN", "env:TEST_OKTA_TOKEN")
	t.Setenv("TEST_OKTA_TOKEN", "tok")
	t.Setenv("TESSERA_ENTRA_TENANT_ID", "11111111-2222-3333-4444-555555555555")
	t.Setenv("TESSERA_ENTRA_CLIENT_ID", "cid")
	t.Setenv("TESSERA_ENTRA_CLIENT_SECRET", "env:TEST_ENTRA_SECRET")
	t.Setenv("TEST_ENTRA_SECRET", "s")
	t.Setenv("TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY", "env:TEST_GOOGLE_KEY")
	t.Setenv("TEST_GOOGLE_KEY", testServiceAccountKey(t))
	t.Setenv("TESSERA_GOOGLE_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("TESSERA_WORKDAY_BASE_URL", "https://wd2-impl-services1.workday.com")
	t.Setenv("TESSERA_WORKDAY_TENANT", "fixture_tenant")
	t.Setenv("TESSERA_WORKDAY_CLIENT_ID", "cid")
	t.Setenv("TESSERA_WORKDAY_CLIENT_SECRET", "env:TEST_WORKDAY_SECRET")
	t.Setenv("TEST_WORKDAY_SECRET", "s")
	conns, err := connectors.Load("demo-workday,okta,entra,google,workday", now)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range conns {
		got = append(got, c.TypeName())
	}
	if strings.Join(got, ",") != "DemoWorkdayConnector,OktaConnector,EntraConnector,GoogleConnector,WorkdayConnector" {
		t.Errorf("connectors = %v", got)
	}
}

func TestLoadRefusesAnUnsafeOrIncompleteConfiguration(t *testing.T) {
	register(t)
	for _, tc := range []struct{ name, spec string }{{"okta unconfigured", "okta"}, {"entra unconfigured", "entra"},
		{"google unconfigured", "google"}, {"workday unconfigured", "workday"}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"TESSERA_OKTA_ORG_URL", "TESSERA_OKTA_API_TOKEN", "TESSERA_ENTRA_TENANT_ID",
				"TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY", "TESSERA_WORKDAY_BASE_URL"} {
				t.Setenv(k, "")
				_ = os.Unsetenv(k)
			}
			if _, err := connectors.Load(tc.spec, now); err == nil {
				t.Error("Load succeeded without configuration")
			}
		})
	}
	t.Run("http org URL in prod", func(t *testing.T) {
		t.Setenv("TESSERA_ENV", "prod")
		t.Setenv("TESSERA_OKTA_ORG_URL", "http://example.okta.com")
		t.Setenv("TESSERA_OKTA_API_TOKEN", "env:TEST_OKTA_TOKEN")
		t.Setenv("TEST_OKTA_TOKEN", "tok")
		if _, err := connectors.Load("okta", now); err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("err = %v, want a refusal of a non-https URL", err)
		}
	})
}

// testClient is a safehttp test client that reaches srv.
func testClient(t testing.TB, srv *connsynctest.Server, maxBody int64) *http.Client {
	t.Helper()
	hc, err := safehttp.NewForTest(t, srv.Options(maxBody))
	if err != nil {
		t.Fatal(err)
	}
	return hc
}
