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

// The GitHub scan, PAM vault and ERP connectors are built from the stored config (issue #814): they are
// marked connection-backed (they replace the env-configured connector of the system), read the same data,
// take a dev base URL override only in dev, and a refusal never echoes the credential.
func TestGitHubPAMERPConnectorsAreConnectionBacked(t *testing.T) {
	type rig struct {
		p      governed.Params
		n      governed.Net
		system string
		key    string // the dev base URL override
	}
	var rigs []rig
	gp, gn := githubRig(t)
	rigs = append(rigs, rig{gp, gn, "github-scan", "TESSERA_GITHUB_SCAN_API_URL"})
	for _, v := range []string{governed.CyberArk, governed.Delinea, governed.BeyondTrust} {
		p, n, _ := pamRig(t, v, false)
		rigs = append(rigs, rig{p, n, v, "TESSERA_" + strings.ToUpper(v) + "_BASE_URL"})
	}
	for _, s := range []string{governed.SAP, governed.Oracle} {
		p, n := erpRig(t, s)
		rigs = append(rigs, rig{p, n, s, "TESSERA_" + strings.ToUpper(s) + "_BASE_URL"})
	}
	for _, tc := range rigs {
		t.Run(tc.p.Type, func(t *testing.T) {
			cn, err := wire.Connector(tc.p, tc.n)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != tc.system {
				t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
			}
			if tc.p.Type != governed.GitHubScan {
				if res, err := cn.Discover(context.Background()); err != nil || res.Stats == nil {
					t.Fatalf("res = %+v, err = %v", res, err)
				}
			}
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
			// a metadata host never opens, and the error does not echo the credential
			tc.n.Endpoints = nil
			tc.p.BaseURL = "https://169.254.169.254"
			if _, err := wire.Connector(tc.p, tc.n); err == nil || strings.Contains(err.Error(), tc.p.Secret) {
				t.Errorf("metadata host: %v", err)
			}
		})
	}
}

// A missing credential fails closed: the connector does not open, so the env-configured one is not read.
func TestGitHubPAMERPRefuseAMissingCredential(t *testing.T) {
	gp, gn := githubRig(t)
	pp, pn, _ := pamRig(t, governed.CyberArk, false)
	ep, en := erpRig(t, governed.SAP)
	for _, tc := range []struct {
		p governed.Params
		n governed.Net
	}{{gp, gn}, {pp, pn}, {ep, en}} {
		tc.p.Secret = ""
		if _, err := wire.Connector(tc.p, tc.n); err == nil || !strings.Contains(err.Error(), "no stored credential") {
			t.Errorf("%s: %v", tc.p.Type, err)
		}
	}
}
