// Package wire opens governed connections (internal/connectors/governed) with
// the existing connector packages: it builds a connector through each
// connector's own FromEnv mapping and a read-only prober over its client. It is
// separate from package governed because it imports every connector package,
// and the readiness packages (which only need the registry and the settings)
// must not: the connectors' tests import ingest, which imports readiness. The
// server hands these functions to readiness (readiness.GovOptions).
package wire

import (
	"context"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentcore"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentforce"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/azurerbac"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/bedrockagents"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/copilotstudio"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/entra"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/foundryagents"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/gcpiam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/githubscan"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/google"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/kubernetes"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/mcpserver"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/okta"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sftpdrop"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sqldb"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/successfactors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vault"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vertexagents"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/workday"
)

// Connector builds the connector of a connection by the connector's own
// FromEnv, so a governed connection reads exactly what the env-configured one
// does. rt and hc are the server's (the validated runtime and the safehttp
// client); the result reports Stats so the dry run's data checks have counts.
func Connector(p governed.Params, n governed.Net) (connectors.Connector, error) {
	rt, hc, now := n.RT, n.HC, n.Now
	if governed.IsStored(p.Type) {
		return stored(p, n)
	}
	getenv, err := p.Env()
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	var cn connectors.Connector
	switch p.Type {
	case governed.CyberArk, governed.Delinea, governed.BeyondTrust:
		cn, err = pam.FromEnv(p.Type, getenv, rt, hc, now)
	case governed.SAP, governed.Oracle:
		cn, err = erp.FromEnv(p.Type, getenv, rt, hc, now)
	case governed.GitHubScan:
		cn, err = githubscan.FromEnv(getenv, now(), rt, hc)
	case governed.AgentCore:
		cn, err = agentcore.FromEnv(getenv, now())
	case governed.UnixSSH:
		cn, err = unixssh.FromEnv(getenv, rt)
	case governed.MCP:
		cn, err = mcpserver.FromEnv(getenv, rt, hc, now)
	case governed.Bedrock:
		if getenv, err = n.Overrides(getenv); err != nil {
			return nil, err
		}
		cn, err = bedrockagents.FromEnv(getenv, rt, hc, now)
	case governed.Vertex, governed.Foundry, governed.Copilot, governed.Agentforce:
		if getenv, err = n.Overrides(getenv); err != nil {
			return nil, err
		}
		switch p.Type {
		case governed.Vertex:
			cn, err = vertexagents.FromEnv(getenv, rt, hc, now)
		case governed.Foundry:
			cn, err = foundryagents.FromEnv(getenv, rt, hc, now)
		case governed.Copilot:
			cn, err = copilotstudio.FromEnv(getenv, rt, hc, now)
		default:
			cn, err = agentforce.FromEnv(getenv, rt, hc, now)
		}
	case governed.SFTPDrop:
		cn, err = sftpdrop.FromEnv(getenv, rt)
	}
	if err != nil {
		return nil, err
	}
	return &counted{Connector: cn}, nil
}

// stored builds the connector of a Google Workspace, Workday, Okta, Entra, Salesforce, REST, SQL, ServiceNow, Atlassian, SuccessFactors, Kubernetes, Vault, Azure RBAC, GCP IAM, GitHub scan, PAM vault, ERP, Unix SSH, SFTP drop, MCP server or agent platform connection from its stored config (a Google
// connection's org units, customer and domain, a Workday connection's host and api_version, an Okta org URL, an Entra
// tenant and cloud scope the read). The
// connector replaces an env-configured one of the system (connectors.ConnectionBacked).
func stored(p governed.Params, n governed.Net) (connectors.Connector, error) {
	getenv, err := n.Overrides(func(string) string { return "" })
	if err != nil {
		return nil, err
	}
	now := n.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	var cn connectors.Connector
	switch p.Type {
	case governed.Workday:
		cn, err = workday.FromStored(workday.Stored{TenantHost: p.TenantHost, APIVersion: p.APIVersion, Credential: p.Secret},
			getenv, n.RT, n.HC, now)
	case governed.ServiceNow:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		user := set("username")
		if set("auth_mode") == servicenow.AuthOAuth {
			user = set("client_id")
		}
		cn, err = servicenow.FromStored(servicenow.Stored{BaseURL: p.BaseURL, AuthMode: set("auth_mode"), Username: user, Credential: p.Secret},
			getenv, n.RT, n.HC, now)
	case governed.Atlassian:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = atlassian.FromStored(atlassian.Stored{BaseURL: p.BaseURL, Email: set("email"), OrgID: set("org_id"), ProjectKeys: set("project_keys"),
			Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.SuccessFactors:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = successfactors.FromStored(successfactors.Stored{BaseURL: p.BaseURL, CompanyID: set("company_id"), Auth: set("auth"),
			Username: set("username"), UserID: set("user_id"), ClientID: set("client_id"), LegalEntity: set("legal_entity"), Credential: p.Secret},
			getenv, n.RT, n.HC)
	case governed.Kubernetes:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = kubernetes.FromStored(kubernetes.Stored{BaseURL: p.BaseURL, Namespaces: set("namespaces"), OpenShift: set("openshift"),
			Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.Vault:
		cn, err = vault.FromStored(vault.Stored{BaseURL: p.BaseURL, Namespace: strings.TrimSpace(p.Settings["namespace"]), Credential: p.Secret},
			getenv, n.RT, n.HC, now)
	case governed.AzureRBAC:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = azurerbac.FromStored(azurerbac.Stored{TenantID: set("tenant_id"), ClientID: set("client_id"), SubscriptionIDs: set("subscription_ids"),
			ManagementGroupIDs: set("management_group_ids"), IncludeEligible: set("include_eligible"), Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.GCPIAM:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = gcpiam.FromStored(gcpiam.Stored{OrganizationID: set("organization_id"), FolderIDs: set("folder_ids"), ProjectIDs: set("project_ids"),
			Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.GitHubScan:
		cn, err = githubscan.FromStored(githubscan.Stored{Org: strings.TrimSpace(p.Settings["org"]), BaseURL: p.BaseURL, Credential: p.Secret},
			getenv, n.RT, n.HC)
	case governed.CyberArk, governed.Delinea, governed.BeyondTrust:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = pam.FromStored(pam.Stored{Vendor: p.Type, BaseURL: p.BaseURL, Username: set("username"), APIRoot: set("api_root"), Credential: p.Secret},
			getenv, n.RT, n.HC, now)
	case governed.SAP, governed.Oracle:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = erp.FromStored(erp.Stored{System: p.Type, BaseURL: p.BaseURL, ClientID: set("client_id"), APIRoot: set("api_root"), TokenPath: set("token_path"),
			Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.UnixSSH:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = unixssh.FromStored(unixssh.Stored{Host: set("host"), Port: set("port"), Username: set("username"), HostKey: set("host_key"),
			UseSudo: set("use_sudo"), Credential: p.Secret}, n.RT)
	case governed.SFTPDrop:
		cn, err = sftpdrop.FromStored(sftpdrop.Stored{Settings: p.Settings, Credential: p.Secret}, n.RT)
	case governed.MCP:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = mcpserver.FromStored(mcpserver.Stored{URL: p.BaseURL, Owner: set("owner"), Name: set("server_name"), AuthHeader: set("auth_header"),
			Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.Bedrock:
		cn, err = bedrockagents.FromStored(bedrockagents.Stored{Region: strings.TrimSpace(p.Settings["region"]), Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.Vertex:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = vertexagents.FromStored(vertexagents.Stored{ProjectID: set("project_id"), Location: set("location"), Owner: set("owner"),
			Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.Foundry:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = foundryagents.FromStored(foundryagents.Stored{BaseURL: p.BaseURL, TenantID: set("tenant_id"), ClientID: set("client_id"), Owner: set("owner"),
			Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.Copilot:
		set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
		cn, err = copilotstudio.FromStored(copilotstudio.Stored{BaseURL: p.BaseURL, TenantID: set("tenant_id"), ClientID: set("client_id"),
			Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.Agentforce:
		cn, err = agentforce.FromStored(agentforce.Stored{BaseURL: p.BaseURL, APIVersion: strings.TrimSpace(p.Settings["api_version"]), Credential: p.Secret},
			getenv, n.RT, n.HC, now)
	case governed.AgentCore:
		var path string
		if path, err = p.SnapshotPath(); err == nil {
			cn, err = agentcore.FromStored(agentcore.Stored{Snapshot: path, Prod: p.Prod || n.RT.Env == config.Prod})
		}
	case governed.Salesforce:
		cn, err = salesforce.FromStored(salesforce.Stored{BaseURL: p.BaseURL, APIVersion: p.APIVersion, Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.Okta:
		cn, err = okta.FromStored(okta.Stored{OrgURL: p.OrgURL, Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.Entra:
		cn, err = entra.FromStored(entra.Stored{TenantID: p.TenantID, Cloud: p.Cloud, Credential: p.Secret}, getenv, n.RT, n.HC, now)
	case governed.RestGeneric:
		cn, err = restgen.FromStored(p.Rest, p.Secret, storedRuntime(n.RT), n.HC)
	case governed.SQL:
		cn, err = sqldb.FromStored(p.SQL, p.Secret, storedRuntime(n.RT))
	default:
		cn, err = google.FromStored(google.Stored{Customer: p.Customer, Domain: p.Domain, OrgUnits: p.OrgUnits, AdminEmail: p.AdminEmail, Credential: p.Secret},
			getenv, n.RT, n.HC, now)
	}
	if err != nil {
		return nil, err
	}
	return &connectionBacked{counted{Connector: cn}}, nil
}

// storedRuntime is the policy a stored REST or SQL connection is opened under: only a dev runtime is
// dev; any other environment name gets the production rules (as a save does), and the dialer refuses
// an environment it does not know.
func storedRuntime(rt connsync.Runtime) connsync.Runtime {
	if rt.Env == config.Dev {
		return rt
	}
	return connsync.Runtime{Env: config.Prod}
}

// connectionBacked marks a connector built from a connection's stored config.
type connectionBacked struct{ counted }

func (*connectionBacked) ConnectionBacked() {}

// counted adds the class counts the readiness data checks read (the
// connector's own result is otherwise untouched): one "user" class over the
// connector's accounts, with how many carry an id, a username and a status and
// how many ids are distinct.
type counted struct{ connectors.Connector }

func (c *counted) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	res, err := c.Connector.Discover(ctx)
	if err != nil || res == nil || res.Stats != nil {
		return res, err
	}
	sys := c.System()
	var total, id, name, status int
	ids := map[string]bool{}
	for _, a := range res.Accounts {
		if a.System != sys {
			continue
		}
		total++
		if a.ExternalID != "" {
			id++
			ids[a.ExternalID] = true
		}
		if a.Username != "" {
			name++
		}
		if a.Status != "" {
			status++
		}
	}
	if total > 0 {
		res.Stats = &connectors.DiscoveryStats{Classes: map[string]*connectors.ClassStats{"user": {Total: total,
			Attributes: map[string]connectors.AttrStat{
				"id":       {Present: id, Distinct: len(ids)},
				"username": {Present: name, Distinct: name},
				"status":   {Present: status, Distinct: status},
			}}}}
	}
	return res, nil
}
