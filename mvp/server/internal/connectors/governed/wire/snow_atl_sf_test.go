package wire_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
)

// ServiceNow, Atlassian and SuccessFactors connectors are built from the stored config (issue #814): they
// are marked connection-backed (they replace the env-configured connector of the system), the dev base
// URL override applies only in dev, and a refusal never echoes the credential.
func TestSnowAtlassianSuccessFactorsConnectorsAreConnectionBacked(t *testing.T) {
	sn, snN, _ := snRig(t, false)
	at, atN, _ := atRig(t, true)
	srv, sfN := serve(t, sfFake(t))
	sf := sfParams(srv.URL, sfPassword)
	for _, tc := range []struct {
		p      governed.Params
		n      governed.Net
		system string
		key    string
	}{
		{sn, snN, "servicenow", "TESSERA_SERVICENOW_BASE_URL"},
		{at, atN, "atlassian", "TESSERA_ATLASSIAN_BASE_URL"},
		{sf, sfN, "successfactors", "TESSERA_SUCCESSFACTORS_BASE_URL"},
	} {
		t.Run(tc.system, func(t *testing.T) {
			cn, err := wire.Connector(tc.p, tc.n)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != tc.system {
				t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
			}
			if _, err := cn.Discover(context.Background()); err != nil {
				t.Fatal(err)
			}
			// the dev override replaces the stored base URL; outside dev any override is refused
			real := tc.p.BaseURL
			tc.p.BaseURL = "https://acme.example.com"
			tc.n.Endpoints = map[string]string{tc.key: real}
			if _, err := wire.Connector(tc.p, tc.n); err != nil {
				t.Errorf("dev override: %v", err)
			}
			tc.n.RT = connsync.Runtime{Env: config.Prod}
			if _, err := wire.Connector(tc.p, tc.n); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
				t.Errorf("prod with an override: %v", err)
			}
			tc.n.Endpoints = nil
			tc.p.BaseURL = "https://169.254.169.254"
			tc.p.Secret = "SECRET-VALUE"
			if _, err := wire.Connector(tc.p, tc.n); err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
				t.Errorf("metadata host: %v", err)
			}
		})
	}
}
