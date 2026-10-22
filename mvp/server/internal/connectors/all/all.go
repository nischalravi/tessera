// Package all registers the production connectors with connectors.Factories,
// so TESSERA_CONNECTORS=okta,entra,google,workday (or any mix with the demo-*
// names) works.
//
// It is a separate package because the connectors import package connectors
// for the record types, so package connectors cannot import them back. The
// server binary calls Register once it has built its outbound client:
//
//	all.Register(outbound, connsync.RuntimeFromConfig(cfg))
//
// The default stays the demo company: nothing here runs unless the spec names
// a production name (okta, entra, google or workday). Credentials and URLs are
// read from TESSERA_OKTA_*, TESSERA_ENTRA_*, TESSERA_GOOGLE_* and
// TESSERA_WORKDAY_* when the connector is built, never earlier. The connectors
// use the shared client they are given (safehttp.ForConfig) and never build
// their own.
package all

import (
	"net/http"
	"os"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentcore"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/entra"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/githubscan"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/google"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/okta"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/workday"
)

// Agent discovery (issue #116): "github-scan" reads MCP configs and agent
// credentials from a GitHub org (TESSERA_GITHUB_SCAN_*); "aws-agentcore" reads
// a recorded AgentCore snapshot (TESSERA_AGENTCORE_SNAPSHOT) and refuses prod,
// as no live AgentCore client exists. Entra and Okta discover agents when
// TESSERA_ENTRA_DISCOVER_AGENTS / TESSERA_OKTA_DISCOVER_AGENTS is true.
//
// Privileged-access vaults (issue #304): "cyberark", "delinea" and "beyondtrust" read safes, their
// members and vaulted accounts (TESSERA_CYBERARK_*, TESSERA_DELINEA_*, TESSERA_BEYONDTRUST_*).
//
// Register adds the okta, entra, google, workday, github-scan and aws-agentcore factories. hc is the
// server's shared outbound client and rt comes from the validated configuration.
func Register(hc *http.Client, rt connsync.Runtime) {
	connectors.Factories["okta"] = func(now time.Time) (connectors.Connector, error) {
		return okta.FromEnv(os.Getenv, now, rt, hc)
	}
	connectors.Factories["entra"] = func(now time.Time) (connectors.Connector, error) {
		return entra.FromEnv(os.Getenv, now, rt, hc)
	}
	connectors.Factories["google"] = func(now time.Time) (connectors.Connector, error) {
		return google.FromEnv(os.Getenv, now, rt, hc)
	}
	connectors.Factories["workday"] = func(now time.Time) (connectors.Connector, error) {
		return workday.FromEnv(os.Getenv, now, rt, hc)
	}
	connectors.Factories["github-scan"] = func(now time.Time) (connectors.Connector, error) {
		return githubscan.FromEnv(os.Getenv, now, rt, hc)
	}
	for _, vendor := range pam.Vendors {
		connectors.Factories[vendor] = func(now time.Time) (connectors.Connector, error) {
			return pam.FromEnv(vendor, os.Getenv, rt, hc, func() time.Time { return now })
		}
	}
	connectors.Factories["aws-agentcore"] = func(now time.Time) (connectors.Connector, error) {
		return agentcore.FromEnv(os.Getenv, now)
	}
}
