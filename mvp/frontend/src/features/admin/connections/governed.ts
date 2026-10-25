// Connect-step fields of the governed connector types (the connectors that already exist in the server:
// AWS Organizations, GitHub scan, SAP, Oracle, the privileged-access vaults, the contractor feeds and
// AgentCore, SuccessFactors). Pure, so `npm test` covers it. The setting keys mirror internal/connectors/governed
// (SettingSpecs); a Go test compares them with SETTING_KEYS below, so the two cannot drift.

export interface GovField { key: string; label: string; hint?: string; required?: boolean; area?: boolean; /** A Yes/No select; the server takes the string "true" or "false". */ flag?: boolean }
export interface GovCredential { label: string; hint: string; area?: boolean }
export interface GovType {
  /** The base URL field, when the type takes one (GitHub's is optional). */
  baseUrl?: { label: string; hint: string; required: boolean };
  settings: GovField[];
  /** null: the type holds no credential (a recorded AgentCore snapshot). */
  credential: GovCredential | null;
}

/** The non-secret setting keys of each governed connector type, in display order. */
export const SETTING_KEYS: Record<string, string[]> = {
  awsorg: ["role_name", "regions", "account_ids", "management_account_id", "identity_center_region", "external_id"],
  githubscan: ["org"],
  sap: ["client_id", "api_root", "token_path"],
  oracle: ["client_id", "api_root", "token_path"],
  cyberark: ["username", "api_root"],
  beyondtrust: ["username", "api_root"],
  delinea: ["username", "api_root"],
  fieldglass: ["workers_path", "token_path", "page_size"],
  beeline: ["workers_path", "token_path", "page_size"],
  csvfeed: ["csv_path"],
  agentcore: ["snapshot"],
  successfactors: ["auth", "company_id", "username", "user_id", "client_id", "legal_entity"],
  azurerbac: ["tenant_id", "client_id", "subscription_ids", "management_group_ids", "include_eligible"],
  gcpiam: ["organization_id", "folder_ids", "project_ids"],
  servicenow: ["auth_mode", "username", "client_id"],
  atlassian: ["email", "org_id", "project_keys"],
  unixssh: ["host", "port", "username", "host_key", "use_sudo"],
  mcp: ["owner", "server_name", "auth_header"],
  bedrock: ["region"],
  vertex: ["project_id", "location", "owner"],
  foundry: ["tenant_id", "client_id", "owner"],
  copilot: ["tenant_id", "client_id"],
  agentforce: ["api_version"],
  kubernetes: ["namespaces", "openshift"],
  vault: ["namespace"],
  sftpdrop: ["host", "port", "username", "host_key", "directory", "accounts_file", "entitlements_file", "accounts_account_id", "accounts_username", "accounts_email", "accounts_identity_id", "accounts_status", "entitlements_account_id", "entitlements_entitlement", "entitlements_name", "entitlements_privileged"],
};

const VAULT_URL = { label: "Vault URL", hint: "The vault's HTTPS host name, no path.", required: true };
const vault = (user: string, secret: GovCredential): GovType => ({
  baseUrl: VAULT_URL,
  settings: [
    { key: "username", label: user, required: true, hint: "A dedicated account with read access to safes, members and accounts." },
    { key: "api_root", label: "API root path", hint: "Only when the vendor's default path is changed." },
  ],
  credential: secret,
});
const erp = (host: string): GovType => ({
  baseUrl: { label: "System URL", hint: `${host}; HTTPS host name, no path.`, required: true },
  settings: [
    { key: "client_id", label: "OAuth client id", required: true, hint: "The integration's client. Its secret is the credential." },
    { key: "api_root", label: "Authorization service path", hint: "Optional." },
    { key: "token_path", label: "OAuth token path", hint: "Optional." },
  ],
  credential: { label: "Client secret", hint: "The integration's OAuth client secret." },
});
const feed = (host: string): GovType => ({
  baseUrl: { label: "Base URL", hint: `${host}; HTTPS host name, no path (the paths are settings).`, required: true },
  settings: [
    { key: "workers_path", label: "Worker listing path", hint: "Default: Fieldglass /api/v1/workers, Beeline /api/v2/assignments." },
    { key: "token_path", label: "OAuth token path", hint: "Default /api/oauth2/v2.0/token." },
    { key: "page_size", label: "Page size", hint: "1 to 1000, default 100." },
  ],
  credential: { label: "Client id and secret", hint: "client_id:client_secret of the integration." },
});

export const GOVERNED: Record<string, GovType> = {
  awsorg: {
    settings: [
      { key: "role_name", label: "Reader role name", hint: "The role assumed in each account. Default TesseraReader." },
      { key: "regions", label: "Regions", required: true, hint: "Comma separated; the first is where STS is called." },
      { key: "account_ids", label: "Account ids", hint: "Comma separated. Empty with a management account: every active account." },
      { key: "management_account_id", label: "Management account id", hint: "Set for an organization-wide read." },
      { key: "identity_center_region", label: "Identity Center region", hint: "Empty skips IAM Identity Center." },
      { key: "external_id", label: "External id", required: true, hint: "The sts:ExternalId in the reader role's trust policy. Stored-key connections only (not allowed in production); prefer a federated connector (docs: AWS connector)." },
    ],
    credential: { label: "Access keys (JSON)", hint: '{"access_key_id": "...", "secret_access_key": "..."}. The keys may only assume the reader role.', area: true },
  },
  githubscan: {
    baseUrl: { label: "API URL", hint: "Empty is GitHub.com. GitHub Enterprise Server: https://host/api/v3.", required: false },
    settings: [{ key: "org", label: "Organization", required: true, hint: "The GitHub organization to scan." }],
    credential: { label: "Token", hint: "A fine-grained token with Contents: read and Metadata: read only." },
  },
  sap: erp("https://s4.example.com"),
  oracle: erp("https://fa.example.com"),
  cyberark: vault("Service user", { label: "Password", hint: "The service user's password." }),
  beyondtrust: vault("Run-as user", { label: "API key", hint: "The Password Safe API key." }),
  delinea: vault("Service user", { label: "Password", hint: "The service user's password." }),
  fieldglass: feed("https://example.fieldglass.net"),
  beeline: feed("https://example.beeline.com"),
  csvfeed: {
    baseUrl: { label: "Base URL", hint: "HTTPS host name, no path.", required: true },
    settings: [{ key: "csv_path", label: "CSV path under the base URL", required: true, hint: "The feed is fetched over HTTPS. Uploads stay on the Contractors page." }],
    credential: { label: "Bearer token", hint: "Sent as Authorization: Bearer." },
  },
  successfactors: {
    baseUrl: { label: "API server", hint: "https://api4.successfactors.com (or your data center's *.successfactors.com, *.successfactors.eu, *.sapsf.com, *.sapsf.cn, *.sapsf.eu host); host name only, no path.", required: true },
    settings: [
      { key: "auth", label: "Authentication", hint: "basic (default) or saml_bearer. With saml_bearer the credential is the PEM private key and certificate registered on the OAuth client." },
      { key: "company_id", label: "Company id", required: true, hint: "The SuccessFactors company id." },
      { key: "username", label: "API user", required: true, hint: "A dedicated API user with read-only permissions. The login name for basic authentication." },
      { key: "user_id", label: "SAML user id", hint: "With saml_bearer: the user id the assertion is issued for, when it differs from the login name. Default: the API user." },
      { key: "client_id", label: "OAuth client id (API key)", hint: "Required with saml_bearer." },
      { key: "legal_entity", label: "Legal entity", hint: "Optional: read only the jobs of this legal entity." },
    ],
    credential: { label: "Password or key bundle", hint: "basic: the API user's password. saml_bearer: a PEM bundle with the RSA private key and its certificate. Read-only: Tessera never writes to SuccessFactors.", area: true },
  },
  azurerbac: {
    settings: [
      { key: "tenant_id", label: "Directory (tenant) id", required: true, hint: "The Entra tenant GUID." },
      { key: "client_id", label: "Application (client) id", required: true, hint: "A service principal with Reader at the scopes to read." },
      { key: "subscription_ids", label: "Subscription ids", hint: "Comma separated GUIDs. Empty with no management groups: every subscription the application can list." },
      { key: "management_group_ids", label: "Management group ids", hint: "Comma separated. Empty with no subscriptions: every management group it can list." },
      { key: "include_eligible", label: "Read PIM eligible assignments", hint: "true or false (default false). Needs Entra ID P2." },
    ],
    credential: { label: "Client secret or certificate", hint: "The client secret, or a PEM holding the certificate and its RSA private key (certificate sign-in).", area: true },
  },
  gcpiam: {
    settings: [
      { key: "organization_id", label: "Organization id", hint: "The numeric organization id; its folders and projects are walked." },
      { key: "folder_ids", label: "Folder ids", hint: "Comma separated numeric ids; each is walked. Optional." },
      { key: "project_ids", label: "Project ids", hint: "Comma separated. Set at least one of organization, folders or projects." },
    ],
    credential: { label: "Service account key (JSON)", hint: "The whole key file of a service account with viewer roles (Security Reviewer).", area: true },
  },
  servicenow: {
    baseUrl: { label: "Instance URL", hint: "https://name.service-now.com (or name.servicenowservices.com); HTTPS host name, no path.", required: true },
    settings: [
      { key: "auth_mode", label: "Sign-in", hint: "basic (default: an integration user and its password) or oauth (an OAuth client with the client credentials grant)." },
      { key: "username", label: "Integration user", hint: "Required for basic: a dedicated user with read access to the user, group, group member and role tables." },
      { key: "client_id", label: "OAuth client id", hint: "Required for oauth: the client id of the instance's OAuth inbound integration." },
    ],
    credential: { label: "Password or client secret", hint: "The integration user's password (basic) or the OAuth client secret (oauth)." },
  },
  atlassian: {
    baseUrl: { label: "Site URL", hint: "https://name.atlassian.net; HTTPS host name, no path.", required: true },
    settings: [
      { key: "email", label: "Account e-mail", required: true, hint: "The dedicated account whose API token is the credential. Accounts are provisioned on the Atlassian Cloud SCIM tile." },
      { key: "org_id", label: "Organization id", hint: "Optional: adds product access from the organization admin API; the credential is then JSON." },
      { key: "project_keys", label: "Project keys", hint: "Comma separated, at most 50. Optional: the projects whose project roles are read." },
    ],
    credential: { label: "API token", hint: "The account's API token. With an organization id: {\"api_token\": \"...\", \"admin_api_key\": \"...\"}.", area: true },
  },
  unixssh: {
    settings: [
      { key: "host", label: "Host", required: true, hint: "The host name or IP address. Private, loopback and link-local addresses are refused from the server." },
      { key: "port", label: "SSH port", hint: "1 to 65535, default 22." },
      { key: "username", label: "SSH user", required: true, hint: "A dedicated, unprivileged account. It runs only getent, lastlog and the sudoers read." },
      { key: "host_key", label: "Host key", required: true, hint: "The pinned host key: a SHA256 fingerprint (ssh-keygen -lf) or the public key line. A host whose key differs is refused." },
      { key: "use_sudo", label: "Read sudoers through sudo", hint: "true or false (default false). Needs NOPASSWD sudo entries for exactly the two read commands (see the README)." },
    ],
    credential: { label: "SSH private key", hint: "The private key (PEM or OpenSSH format, no passphrase) whose public key is in the login's authorized_keys.", area: true },
  },
  mcp: {
    baseUrl: { label: "MCP endpoint", hint: "https://host/mcp: the server's Streamable HTTP endpoint, HTTPS only. Private, loopback and link-local addresses are refused from the server.", required: true },
    settings: [
      { key: "owner", label: "Owner", required: true, hint: "The e-mail address of the person accountable for the server. MCP carries no owner, so its tools are linked to this person." },
      { key: "server_name", label: "Display name", hint: "Optional. Default: the name the server reports, then its host." },
      { key: "auth_header", label: "Credential header", hint: "Optional. The header an API key goes in (X-Api-Key). Default: Authorization: Bearer." },
    ],
    credential: { label: "Bearer token or API key", hint: "A token that may list tools. Tessera never calls a tool. It also tries the server without it, to record whether it accepts anonymous callers." },
  },
  bedrock: {
    settings: [{ key: "region", label: "Region", required: true, hint: "The AWS region whose agents are read, for example us-east-1. Agents are regional: add one connection per region." }],
    credential: { label: "AWS keys (JSON)", hint: "{\"access_key_id\": \"...\", \"secret_access_key\": \"...\", \"session_token\": \"...\"} of a principal with the Bedrock agent list and get rights only; session_token is optional.", area: true },
  },
  vertex: {
    settings: [
      { key: "project_id", label: "Project", required: true, hint: "The project id (or number) whose agents are read." },
      { key: "location", label: "Location", required: true, hint: "The region whose agents are read, for example us-central1. Agents are regional: add one connection per location." },
      { key: "owner", label: "Owner", hint: "Optional. The e-mail address of the person accountable for the project's agents; a Vertex agent carries no e-mail address of its own." },
    ],
    credential: { label: "Service account key (JSON)", hint: "The key file of a service account with roles/aiplatform.viewer only.", area: true },
  },
  foundry: {
    baseUrl: { label: "Project endpoint", hint: "https://<account>.services.ai.azure.com/api/projects/<project>: the Foundry project's endpoint, HTTPS only.", required: true },
    settings: [
      { key: "tenant_id", label: "Directory (tenant) id", required: true, hint: "The Entra tenant GUID." },
      { key: "client_id", label: "Application (client) id", required: true, hint: "A service principal with the Azure AI User role on the project (read only)." },
      { key: "owner", label: "Owner", hint: "Optional. The e-mail address of the person accountable for agents whose metadata names no sponsor." },
    ],
    credential: { label: "Client secret or certificate", hint: "The application's client secret, or a PEM with its certificate and RSA private key.", area: true },
  },
  copilot: {
    baseUrl: { label: "Environment URL", hint: "https://<org>.crm.dynamics.com: the Power Platform environment's Dataverse URL, HTTPS only, no path.", required: true },
    settings: [
      { key: "tenant_id", label: "Directory (tenant) id", required: true, hint: "The Entra tenant GUID." },
      { key: "client_id", label: "Application (client) id", required: true, hint: "An application user of the environment with a read-only Dataverse role (read on Chatbot, Chatbot Subcomponent and User)." },
    ],
    credential: { label: "Client secret or certificate", hint: "The application's client secret, or a PEM with its certificate and RSA private key.", area: true },
  },
  agentforce: {
    baseUrl: { label: "My Domain URL", hint: "https://acme.my.salesforce.com: the org's My Domain URL, HTTPS only, no path.", required: true },
    settings: [{ key: "api_version", label: "API version", hint: "Optional, v61.0 and the like." }],
    credential: { label: "Connected app credential (JSON)", hint: "{\"client_id\": \"<consumer key>\", \"username\": \"<integration user>\", \"private_key\": \"-----BEGIN PRIVATE KEY-----...\"}: the JWT bearer flow; no password is kept.", area: true },
  },
  kubernetes: {
    baseUrl: { label: "API server URL", hint: "https://api.cluster.example.com:6443; HTTPS host name and port, no path. Its certificate must chain to a public CA.", required: true },
    settings: [
      { key: "namespaces", label: "Namespaces", hint: "Comma separated, at most 100. Optional: read the roles, role bindings and service accounts of these namespaces only." },
      { key: "openshift", label: "OpenShift", flag: true, hint: "Yes also reads the groups of user.openshift.io (default No)." },
    ],
    credential: { label: "ServiceAccount token", hint: "The bearer token of a ServiceAccount that can only list RBAC objects, service accounts and (OpenShift) groups. Read-only: Tessera never writes to the cluster.", area: true },
  },
  vault: {
    baseUrl: { label: "Vault URL", hint: "https://vault.example.com:8200; HTTPS host name and port, no path.", required: true },
    settings: [
      { key: "namespace", label: "Namespace", hint: "Vault Enterprise namespace path. Optional: one connection reads one namespace." },
    ],
    credential: { label: "Vault token", hint: "A periodic token of a read-only policy (read sys/policies/acl and sys/auth, list and read the auth role, user, group and identity collections). Never a root token. Read-only: no secret is read.", area: true },
  },
  sftpdrop: {
    settings: [
      { key: "host", label: "Host", required: true, hint: "The SFTP server's host name or IP address. Private, loopback and link-local addresses are refused from the server." },
      { key: "port", label: "SSH port", hint: "1 to 65535, default 22." },
      { key: "username", label: "SFTP user", required: true, hint: "A dedicated account that can read the drop directory only." },
      { key: "host_key", label: "Host key", required: true, hint: "The pinned host key: a SHA256 fingerprint (ssh-keygen -lf) or the public key line. A server whose key differs is refused; there is no trust on first use." },
      { key: "directory", label: "Directory", required: true, hint: "The absolute directory the files are read from, as the server reports it. A link, or a path through one, is refused." },
      { key: "accounts_file", label: "Accounts file", required: true, hint: "The plain file name of the accounts CSV (at most 512 KiB and 5000 rows)." },
      { key: "entitlements_file", label: "Entitlements file", hint: "Optional: the plain file name of the account-entitlement CSV, one row per account and entitlement." },
      { key: "accounts_account_id", label: "Accounts: account id column", required: true, hint: "The column that identifies the account." },
      { key: "accounts_username", label: "Accounts: username column", required: true, hint: "The column with the login name." },
      { key: "accounts_email", label: "Accounts: email column", hint: "Optional: correlates the account to a person." },
      { key: "accounts_identity_id", label: "Accounts: identity id column", hint: "Optional: the person's external id, tried before the email." },
      { key: "accounts_status", label: "Accounts: status column", hint: "Optional: active or disabled. Without it every account is active." },
      { key: "entitlements_account_id", label: "Entitlements: account id column", hint: "Required with an entitlements file." },
      { key: "entitlements_entitlement", label: "Entitlements: entitlement column", hint: "Required with an entitlements file." },
      { key: "entitlements_name", label: "Entitlements: name column", hint: "Optional: a display name for the entitlement." },
      { key: "entitlements_privileged", label: "Entitlements: privileged column", hint: "Optional: yes or no." },
    ],
    credential: { label: "SSH private key", hint: "The private key (PEM or OpenSSH format, no passphrase) whose public key is in the login's authorized_keys.", area: true },
  },
  agentcore: {
    settings: [{ key: "snapshot", label: "Snapshot file", required: true, hint: "A recorded AgentCore snapshot (JSON) in this tenant's directory. There is no live AgentCore client; refused in prod." }],
    credential: null,
  },
};

export const isGoverned = (connectorType: string) => connectorType in GOVERNED;

/** Form values of a type's settings, from the saved config. */
export function settingValues(connectorType: string, saved?: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of GOVERNED[connectorType]?.settings ?? []) out[`settings.${f.key}`] = saved?.[f.key] ?? (f.flag ? "false" : "");
  return out;
}

/** The settings object to send: only the type's own keys, blanks left out. Null when nothing changed. */
export function settingsPatch(connectorType: string, values: Record<string, string>, saved?: Record<string, string>): Record<string, string> | null {
  const next: Record<string, string> = {};
  for (const f of GOVERNED[connectorType]?.settings ?? []) {
    const v = (values[`settings.${f.key}`] ?? "").trim();
    if (v && !(f.flag && v === "false" && !saved?.[f.key])) next[f.key] = v; // an untouched No is left unset, as the server's default
  }
  const was = Object.fromEntries(Object.entries(saved ?? {}).filter(([, v]) => v));
  const same = Object.keys(next).length === Object.keys(was).length && Object.entries(next).every(([k, v]) => was[k] === v);
  return same ? null : next;
}

/** Required fields still empty, as labels (the server validates again). */
export function missingRequired(connectorType: string, baseUrl: string, values: Record<string, string>): string[] {
  const t = GOVERNED[connectorType];
  if (!t) return [];
  const out: string[] = [];
  if (t.baseUrl?.required && !baseUrl.trim()) out.push(t.baseUrl.label);
  for (const f of t.settings) if (f.required && !(values[`settings.${f.key}`] ?? "").trim()) out.push(f.label);
  return out;
}
