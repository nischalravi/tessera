// Connect-step fields of the governed connector types (the connectors that already exist in the server:
// AWS Organizations, GitHub scan, SAP, Oracle, the privileged-access vaults, the contractor feeds and
// AgentCore, SuccessFactors). Pure, so `npm test` covers it. The setting keys mirror internal/connectors/governed
// (SettingSpecs); a Go test compares them with SETTING_KEYS below, so the two cannot drift.

export interface GovField { key: string; label: string; hint?: string; required?: boolean; area?: boolean }
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
      { key: "external_id", label: "External id", required: true, hint: "The sts:ExternalId in the reader role's trust policy." },
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
  agentcore: {
    settings: [{ key: "snapshot", label: "Snapshot file", required: true, hint: "A recorded AgentCore snapshot (JSON) in this tenant's directory. There is no live AgentCore client; refused in prod." }],
    credential: null,
  },
};

export const isGoverned = (connectorType: string) => connectorType in GOVERNED;

/** Form values of a type's settings, from the saved config. */
export function settingValues(connectorType: string, saved?: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of GOVERNED[connectorType]?.settings ?? []) out[`settings.${f.key}`] = saved?.[f.key] ?? "";
  return out;
}

/** The settings object to send: only the type's own keys, blanks left out. Null when nothing changed. */
export function settingsPatch(connectorType: string, values: Record<string, string>, saved?: Record<string, string>): Record<string, string> | null {
  const next: Record<string, string> = {};
  for (const f of GOVERNED[connectorType]?.settings ?? []) {
    const v = (values[`settings.${f.key}`] ?? "").trim();
    if (v) next[f.key] = v;
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
