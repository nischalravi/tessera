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

// Kubernetes, Vault, Azure RBAC and GCP IAM connectors are built from the stored config (issue #814): they
// are marked connection-backed (they replace the env-configured connector of the system), read the same
// data, take a dev override only in dev, and a refusal never echoes the credential.
func TestK8sVaultCloudConnectorsAreConnectionBacked(t *testing.T) {
	ksrv, kn := serve(t, k8sFake())
	vsrv, vn := serve(t, vaultFake())
	an := azureNet(t)
	gsrv, gn := serve(t, gcpFake())
	gn.Endpoints = map[string]string{"TESSERA_GCP_CRM_URL": gsrv.URL, "TESSERA_GCP_IAM_URL": gsrv.URL, "TESSERA_GCP_TOKEN_URL": gsrv.URL + "/token"}
	for _, tc := range []struct {
		p      governed.Params
		n      governed.Net
		system string
		key    string // the dev base URL override, where the type has a base URL
	}{
		{governed.Params{Type: governed.Kubernetes, BaseURL: ksrv.URL, Secret: k8sToken, Settings: map[string]string{"openshift": "true"}}, kn, "kubernetes", "TESSERA_KUBERNETES_BASE_URL"},
		{governed.Params{Type: governed.Vault, BaseURL: vsrv.URL, Secret: vaultToken}, vn, "vault", "TESSERA_VAULT_BASE_URL"},
		{azureParams(), an, "azure", ""},
		{gcpParams(t), gn, "gcp", ""},
	} {
		t.Run(tc.system, func(t *testing.T) {
			cn, err := wire.Connector(tc.p, tc.n)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != tc.system {
				t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
			}
			res, err := cn.Discover(context.Background())
			if err != nil || len(res.Permissions) != 1 || !res.Permissions[0].Privileged || res.Stats == nil {
				t.Fatalf("res = %+v, err = %v", res, err)
			}
			if tc.key != "" {
				// the dev override replaces the stored base URL; outside dev any override is refused
				real := tc.p.BaseURL
				tc.p.BaseURL = "https://other.example.com"
				tc.n.Endpoints = map[string]string{tc.key: real}
				if _, err := wire.Connector(tc.p, tc.n); err != nil {
					t.Errorf("dev override: %v", err)
				}
				tc.n.RT = connsync.Runtime{Env: config.Prod}
				if _, err := wire.Connector(tc.p, tc.n); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
					t.Errorf("prod with an override: %v", err)
				}
				tc.n.Endpoints = nil
			}
			// a metadata host or a bad scope never opens, and the error does not echo the credential
			tc.n.Endpoints = nil
			tc.n.RT = connsync.Runtime{Env: config.Prod}
			switch {
			case tc.key != "":
				tc.p.BaseURL = "https://169.254.169.254"
			case tc.system == "azure":
				tc.p.Settings = map[string]string{"tenant_id": "not-a-guid", "client_id": azClient}
			default:
				tc.p.Secret = "SECRET-VALUE" // not a service account key
			}
			if _, err := wire.Connector(tc.p, tc.n); err == nil || strings.Contains(err.Error(), tc.p.Secret) {
				t.Errorf("refused build: %v", err)
			}
		})
	}
}

// A missing credential fails closed: the connector does not open, so the env-configured one is not read.
func TestK8sVaultCloudRefuseAMissingCredential(t *testing.T) {
	ksrv, kn := serve(t, k8sFake())
	for _, p := range []governed.Params{
		{Type: governed.Kubernetes, BaseURL: ksrv.URL},
		{Type: governed.Vault, BaseURL: ksrv.URL},
		func() governed.Params { p := azureParams(); p.Secret = ""; return p }(),
		func() governed.Params { p := gcpParams(t); p.Secret = ""; return p }(),
	} {
		if _, err := wire.Connector(p, kn); err == nil || !strings.Contains(err.Error(), "no stored credential") {
			t.Errorf("%s: %v", p.Type, err)
		}
	}
}
