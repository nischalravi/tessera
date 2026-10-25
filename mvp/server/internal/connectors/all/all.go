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
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/azurerbac"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/bedrockagents"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/entra"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/gcpiam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/githubscan"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/google"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/mcpserver"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/okta"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sqldb"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/successfactors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
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
// ERPs (issue #304): "sap" and "oracle" read roles, t-codes and authorization objects as
// fine-grained entitlements (TESSERA_SAP_*, TESSERA_ORACLE_*).
//
// Salesforce (issue #555): "salesforce" reads users, profiles, roles, permission sets and permission set groups
// (TESSERA_SALESFORCE_*, OAuth JWT bearer flow).
//
// ServiceNow and Atlassian Cloud (issue #559): "servicenow" reads users, groups and roles through the Table API
// (TESSERA_SERVICENOW_*, basic or OAuth client credentials); "atlassian" reads users, groups, project roles and,
// with an organization API key, product access (TESSERA_ATLASSIAN_*). Hosts are *.service-now.com,
// *.servicenowservices.com, *.atlassian.net and api.atlassian.com only.
//
// Generic REST (issue #552): "rest" reads users, groups and entitlements from any HTTP/JSON system as
// a declarative spec describes (TESSERA_REST_SPEC, TESSERA_REST_CREDENTIAL; see internal/connectors/restgen).
//
// Cloud entitlements (issue #557): "azure" reads Azure RBAC role assignments, role definitions and PIM
// eligible assignments (TESSERA_AZURE_*); "gcp" reads Google Cloud IAM policies, roles and service
// accounts (TESSERA_GCP_*). Both reach the public cloud only: an endpoint override is refused in prod.
//
// Unix and Linux over SSH (issue #558): "unix" reads accounts, groups and sudoers rules of one host
// (TESSERA_UNIXSSH_*) with a pinned host key and a key credential; it is read-only.
//
// AI agent platforms (issue #562): "mcp" inventories one MCP server's tools and auth mode (TESSERA_MCP_*, a
// customer-hosted https endpoint reached through safehttp); "bedrock" reads the Amazon Bedrock Agents of one
// region, their action groups and knowledge bases (TESSERA_BEDROCK_*, SigV4 with a key pair). Both are read-only.
//
// Register adds the okta, entra, google, workday, successfactors, rest, sql, salesforce, servicenow, atlassian, azure, gcp, unix, mcp, bedrock, github-scan and aws-agentcore factories. hc is the
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
	// SAP SuccessFactors (issue #556): "successfactors" reads people, jobs and lifecycle events as an
	// HR source (TESSERA_SUCCESSFACTORS_*; see internal/connectors/successfactors).
	connectors.Factories["successfactors"] = func(now time.Time) (connectors.Connector, error) {
		return successfactors.FromEnv(os.Getenv, now, rt, hc)
	}
	connectors.Factories["github-scan"] = func(now time.Time) (connectors.Connector, error) {
		return githubscan.FromEnv(os.Getenv, now, rt, hc)
	}
	for _, vendor := range pam.Vendors {
		connectors.Factories[vendor] = func(now time.Time) (connectors.Connector, error) {
			return pam.FromEnv(vendor, os.Getenv, rt, hc, func() time.Time { return now })
		}
	}
	for _, system := range erp.Systems {
		connectors.Factories[system] = func(now time.Time) (connectors.Connector, error) {
			return erp.FromEnv(system, os.Getenv, rt, hc, func() time.Time { return now })
		}
	}
	connectors.Factories["salesforce"] = func(now time.Time) (connectors.Connector, error) {
		return salesforce.FromEnv(os.Getenv, rt, hc, func() time.Time { return now })
	}
	connectors.Factories["servicenow"] = func(now time.Time) (connectors.Connector, error) {
		return servicenow.FromEnv(os.Getenv, rt, hc, func() time.Time { return now })
	}
	connectors.Factories["atlassian"] = func(now time.Time) (connectors.Connector, error) {
		return atlassian.FromEnv(os.Getenv, rt, hc, func() time.Time { return now })
	}
	connectors.Factories["rest"] = func(time.Time) (connectors.Connector, error) {
		return restgen.FromEnv(os.Getenv, rt, hc)
	}
	// Databases (issue #553): "sql" reads accounts, roles and grants of one PostgreSQL, MySQL,
	// SQL Server or Oracle database (TESSERA_SQL_*). It dials through the safehttp address
	// policy and ignores hc.
	connectors.Factories["sql"] = func(time.Time) (connectors.Connector, error) {
		return sqldb.FromEnv(os.Getenv, os.ReadFile, rt)
	}
	connectors.Factories["azure"] = func(now time.Time) (connectors.Connector, error) {
		return azurerbac.FromEnv(os.Getenv, rt, hc, func() time.Time { return now })
	}
	connectors.Factories["unix"] = func(time.Time) (connectors.Connector, error) {
		return unixssh.FromEnv(os.Getenv, rt)
	}
	connectors.Factories["gcp"] = func(now time.Time) (connectors.Connector, error) {
		return gcpiam.FromEnv(os.Getenv, rt, hc, func() time.Time { return now })
	}
	connectors.Factories["mcp"] = func(now time.Time) (connectors.Connector, error) {
		return mcpserver.FromEnv(os.Getenv, rt, hc, func() time.Time { return now })
	}
	connectors.Factories["bedrock"] = func(now time.Time) (connectors.Connector, error) {
		return bedrockagents.FromEnv(os.Getenv, rt, hc, func() time.Time { return now })
	}
	connectors.Factories["aws-agentcore"] = func(now time.Time) (connectors.Connector, error) {
		return agentcore.FromEnv(os.Getenv, now)
	}
}
