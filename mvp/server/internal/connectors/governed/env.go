package governed

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Net is what a prober or a connector needs of the server: the validated
// runtime, the safehttp client (already allowed the connection's configured
// port) and, for AWS, the factory of its prober (package awsorg implements it;
// it cannot be imported by the readiness packages without a cycle). Now is the
// run's clock.
type Net struct {
	RT  connsync.Runtime
	HC  *http.Client
	AWS func(p Params) (connectors.Prober, error)
	Now func() time.Time
	// Endpoints are dev and test endpoint overrides of the cloud entitlement connectors (a fake
	// Azure, Google or Atlassian admin API), keyed by the connector's own variable (TESSERA_AZURE_*, TESSERA_GCP_*, TESSERA_ATLASSIAN_ADMIN_URL).
	// The server never sets them; a dev runtime applies them and any other runtime refuses a
	// connection that is given one (Overrides).
	Endpoints map[string]string
}

// endpointKeys are the overrides Net.Endpoints may hold.
var endpointKeys = map[string]bool{"TESSERA_AZURE_MANAGEMENT_URL": true, "TESSERA_AZURE_AUTHORITY_URL": true,
	"TESSERA_GCP_CRM_URL": true, "TESSERA_GCP_IAM_URL": true, "TESSERA_GCP_TOKEN_URL": true, "TESSERA_ATLASSIAN_ADMIN_URL": true, "TESSERA_BEDROCK_AGENT_URL": true,
	"TESSERA_VERTEX_API_URL": true, "TESSERA_VERTEX_TOKEN_URL": true, "TESSERA_FOUNDRY_AUTHORITY_URL": true, "TESSERA_COPILOT_AUTHORITY_URL": true}

// Overrides layers n.Endpoints over getenv. It refuses them outside the dev runtime, and refuses an
// unknown key, so a production connection can only reach the public cloud endpoints.
func (n Net) Overrides(getenv func(string) string) (func(string) string, error) {
	if len(n.Endpoints) == 0 {
		return getenv, nil
	}
	if n.RT.Env != config.Dev {
		return nil, errors.New("governed: endpoint overrides are a dev setting and are refused outside dev")
	}
	for k := range n.Endpoints {
		if !endpointKeys[k] {
			return nil, fmt.Errorf("governed: %q is not an endpoint override", k)
		}
	}
	return func(k string) string {
		if v, ok := n.Endpoints[k]; ok {
			return v
		}
		return getenv(k)
	}, nil
}

// Clock returns the run's clock (the wall clock when none is set).
func (n Net) Clock() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now().UTC()
}

// secretVar is the name under which the opened credential is handed to the
// connectors' FromEnv mapping. The mapping reads it through the closure below,
// never from the process environment.
const secretVar = "TESSERA_GOVERNED_SECRET"

// Env returns the environment a connector's FromEnv reads, built from the
// connection: the same variables an operator would export for the legacy,
// env-configured connector, with the credential behind an env: reference that
// only this closure can resolve. The second result is the connector's own
// error when the connection cannot be mapped (a snapshot outside the tenant's
// directory, a prod refusal).
func (p Params) Env() (func(string) string, error) {
	t, ok := Lookup(p.Type)
	if !ok {
		return nil, fmt.Errorf("governed: no connector for type %q", p.Type)
	}
	m := map[string]string{secretVar: p.Secret}
	set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
	pre := "TESSERA_" + strings.ToUpper(t.Vendor) + "_"
	switch p.Type {
	case CyberArk, Delinea, BeyondTrust:
		m[pre+"BASE_URL"], m[pre+"USER"], m[pre+"API_ROOT"] = p.BaseURL, set("username"), set("api_root")
		m[pre+"SECRET"] = "env:" + secretVar
	case SAP, Oracle:
		m[pre+"BASE_URL"], m[pre+"CLIENT_ID"] = p.BaseURL, set("client_id")
		m[pre+"API_ROOT"], m[pre+"TOKEN_PATH"] = set("api_root"), set("token_path")
		m[pre+"CLIENT_SECRET"] = "env:" + secretVar
	case SuccessFactors:
		m[pre+"BASE_URL"], m[pre+"COMPANY_ID"], m[pre+"AUTH"] = p.BaseURL, set("company_id"), set("auth")
		m[pre+"USER"], m[pre+"USER_ID"], m[pre+"CLIENT_ID"], m[pre+"LEGAL_ENTITY"] = set("username"), set("user_id"), set("client_id"), set("legal_entity")
		// the credential is the password (basic) or the key bundle (saml_bearer); the connector reads the one its mode needs
		m[pre+"PASSWORD"], m[pre+"PRIVATE_KEY"] = "env:"+secretVar, "env:"+secretVar
	case GitHubScan:
		m["TESSERA_GITHUB_SCAN_ORG"], m["TESSERA_GITHUB_SCAN_API_URL"] = set("org"), p.BaseURL
		m["TESSERA_GITHUB_SCAN_TOKEN"] = "env:" + secretVar
	case AgentCore:
		path, err := confine(p.DataDir, p.Tenant, set("snapshot"))
		if err != nil {
			return nil, err
		}
		m["TESSERA_AGENTCORE_SNAPSHOT"] = path
		if p.Prod {
			m["TESSERA_ENV"] = config.Prod
		}
	case AzureRBAC:
		m["TESSERA_AZURE_TENANT_ID"], m["TESSERA_AZURE_CLIENT_ID"] = set("tenant_id"), set("client_id")
		m["TESSERA_AZURE_SUBSCRIPTIONS"], m["TESSERA_AZURE_MANAGEMENT_GROUPS"] = set("subscription_ids"), set("management_group_ids")
		m["TESSERA_AZURE_ELIGIBLE"] = set("include_eligible")
		m["TESSERA_AZURE_CREDENTIAL"] = "env:" + secretVar // no endpoint override is ever set: a connection reaches the public cloud only
	case ServiceNow:
		m[pre+"BASE_URL"], m[pre+"AUTH"], m[pre+"USERNAME"], m[pre+"CLIENT_ID"] = p.BaseURL, set("auth_mode"), set("username"), set("client_id")
		m[pre+"SECRET"] = "env:" + secretVar
	case Atlassian:
		m[pre+"BASE_URL"], m[pre+"EMAIL"], m[pre+"ORG_ID"], m[pre+"PROJECTS"] = p.BaseURL, set("email"), set("org_id"), set("project_keys")
		m[pre+"CREDENTIAL"] = "env:" + secretVar // no admin API override is ever set: a connection reaches api.atlassian.com only
	case Kubernetes:
		m[pre+"BASE_URL"], m[pre+"NAMESPACES"], m[pre+"OPENSHIFT"] = p.BaseURL, set("namespaces"), set("openshift")
		m[pre+"TOKEN"] = "env:" + secretVar
	case Vault:
		m[pre+"BASE_URL"], m[pre+"NAMESPACE"] = p.BaseURL, set("namespace")
		m[pre+"TOKEN"] = "env:" + secretVar
	case GCPIAM:
		m["TESSERA_GCP_ORG_ID"], m["TESSERA_GCP_FOLDER_IDS"], m["TESSERA_GCP_PROJECT_IDS"] = set("organization_id"), set("folder_ids"), set("project_ids")
		m["TESSERA_GCP_KEY"] = "env:" + secretVar // likewise no endpoint override
	case MCP:
		m[pre+"URL"], m[pre+"OWNER"], m[pre+"NAME"], m[pre+"AUTH_HEADER"] = p.BaseURL, set("owner"), set("server_name"), set("auth_header")
		m[pre+"TOKEN"] = "env:" + secretVar
	case Bedrock:
		m[pre+"REGION"] = set("region")
		m[pre+"CREDENTIAL"] = "env:" + secretVar // no endpoint override is ever set: a connection reaches the region's public endpoint only
	case Vertex:
		m[pre+"PROJECT"], m[pre+"LOCATION"], m[pre+"OWNER"] = set("project_id"), set("location"), set("owner")
		m[pre+"KEY"] = "env:" + secretVar // no endpoint override is ever set: a connection reaches Google's public endpoints only
	case Foundry:
		m[pre+"ENDPOINT"], m[pre+"TENANT_ID"], m[pre+"CLIENT_ID"], m[pre+"OWNER"] = p.BaseURL, set("tenant_id"), set("client_id"), set("owner")
		m[pre+"CREDENTIAL"] = "env:" + secretVar // likewise no authority override
	case Copilot:
		m[pre+"URL"], m[pre+"TENANT_ID"], m[pre+"CLIENT_ID"] = p.BaseURL, set("tenant_id"), set("client_id")
		m[pre+"CREDENTIAL"] = "env:" + secretVar
	case Agentforce:
		m[pre+"BASE_URL"], m[pre+"API_VERSION"] = p.BaseURL, set("api_version")
		m[pre+"CREDENTIAL"] = "env:" + secretVar
	case UnixSSH:
		m[pre+"HOST"], m[pre+"PORT"], m[pre+"USER"] = set("host"), set("port"), set("username")
		m[pre+"HOST_KEY"], m[pre+"SUDO"] = set("host_key"), set("use_sudo")
		m[pre+"KEY"] = "env:" + secretVar
	case SFTPDrop:
		m[pre+"HOST"], m[pre+"PORT"], m[pre+"USER"], m[pre+"HOST_KEY"] = set("host"), set("port"), set("username"), set("host_key")
		m[pre+"DIR"], m[pre+"ACCOUNTS_FILE"], m[pre+"ENTITLEMENTS_FILE"] = set("directory"), set("accounts_file"), set("entitlements_file")
		m[pre+"COL_ACCOUNT_ID"], m[pre+"COL_USERNAME"], m[pre+"COL_EMAIL"] = set("accounts_account_id"), set("accounts_username"), set("accounts_email")
		m[pre+"COL_IDENTITY_ID"], m[pre+"COL_STATUS"] = set("accounts_identity_id"), set("accounts_status")
		m[pre+"COL_ENT_ACCOUNT_ID"], m[pre+"COL_ENT_ENTITLEMENT"] = set("entitlements_account_id"), set("entitlements_entitlement")
		m[pre+"COL_ENT_NAME"], m[pre+"COL_ENT_PRIVILEGED"] = set("entitlements_name"), set("entitlements_privileged")
		m[pre+"KEY"] = "env:" + secretVar
	default:
		return nil, fmt.Errorf("governed: %s is read by its own feature, not by the connector sync", p.Type)
	}
	return func(k string) string { return m[k] }, nil
}

// confine resolves a snapshot file name under <data dir>/<tenant id>/, the
// directory the tenant's own loader files live in. A name with a directory,
// a symbolic link that leads out and a missing file are refused, so one
// tenant's connection never reads another tenant's file or anything else on
// the server.
func confine(dataDir, tenant, name string) (string, error) {
	switch {
	case dataDir == "":
		return "", errors.New("agentcore: no data directory is configured (TESSERA_LOADER_DATA_DIR)")
	case tenant == "" || strings.ContainsAny(tenant, `/\.`):
		return "", errors.New("agentcore: the snapshot is outside the tenant's directory")
	case !fileRE.MatchString(name) || strings.Contains(name, ".."):
		return "", errors.New("agentcore: the snapshot must be a file name in the tenant's directory")
	}
	base, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return "", errors.New("agentcore: the data directory cannot be opened")
	}
	if base, err = filepath.Abs(base); err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(filepath.Join(base, tenant))
	if err != nil || filepath.Dir(root) != base {
		return "", errors.New("agentcore: the tenant has no data directory")
	}
	full, err := filepath.EvalSymlinks(filepath.Join(root, name))
	if err != nil {
		return "", errors.New("agentcore: the snapshot file cannot be opened")
	}
	if !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", errors.New("agentcore: the snapshot is outside the tenant's directory")
	}
	return full, nil
}
