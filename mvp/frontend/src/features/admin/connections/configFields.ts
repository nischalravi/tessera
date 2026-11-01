// Where the connection wizard renders an input for each config field a server readiness template item declares in
// config_fields (issue #595). Pure data: tests/config-fields.test.ts reads every template, fails when a template field has
// no input here, and checks each `evidence` pattern still matches Wizard.tsx, so a removed input cannot go unnoticed.

export interface FieldInput {
  /** Template ids the input is rendered for. */
  templates: string[];
  /** A RegExp source that must match Wizard.tsx where the input is rendered for those templates. */
  evidence: string;
}

/** Governed connector templates whose Connect step has the base URL and settings inputs (see governed.ts). */
export const GOVERNED_URL_TEMPLATES = ["agentforce", "atlassian", "copilot", "erp", "foundry", "githubscan", "kubernetes", "mcp", "pam", "servicenow", "successfactors", "vault", "vms"];
export const GOVERNED_SETTINGS_TEMPLATES = [...GOVERNED_URL_TEMPLATES, "agentcore", "awsorg", "azurerbac", "bedrock", "gcpiam", "sftpdrop", "unixssh", "vertex"];
const LDAPS = ["ad", "ldap", "racf", "ibmi"];
const WRITERS = ["ad", "ldap", "pam", "erp", "rest_generic"]; // the templates whose Mapping step has write-back
/** Governed templates that still list privileged groups on the Scope step (the others have no privileged item). */
export const PRIVILEGED_GOVERNED = ["atlassian", "servicenow"];

export const WIZARD_INPUTS: Record<string, FieldInput[]> = {
  host: [{ templates: LDAPS, evidence: 'input\\("host"' }],
  port: [{ templates: LDAPS, evidence: 'input\\("port"' }],
  tls_mode: [{ templates: LDAPS, evidence: 'set\\("tls_mode"\\)' }],
  bind_dn: [
    { templates: ["racf"], evidence: 'tid === "racf" && <>\\s*\\{input\\("bind_dn"' },
    { templates: ["ibmi"], evidence: 'tid === "ibmi" && <>\\s*\\{input\\("bind_dn"' },
    { templates: ["ldap"], evidence: 'tid === "ldap" && <>\\s*\\{input\\("bind_dn"' },
  ],
  ca_bundle: [
    { templates: ["racf", "ibmi", "ldap"], evidence: 'area\\("ca_bundle"' },
    { templates: ["sql"], evidence: 'area\\("sql_ca_bundle"' },
  ],
  base_dns: [
    { templates: ["ad", "ldap"], evidence: 'area\\("base_dns", "Base DNs"' },
    { templates: ["racf"], evidence: 'tid === "racf" && area\\("base_dns"' },
    { templates: ["google"], evidence: 'tid === "google" && area\\("base_dns", "Org units"' },
  ],
  user_filter: [{ templates: ["ad", "ldap"], evidence: 'input\\("user_filter"' }],
  group_filter: [{ templates: ["ad", "ldap"], evidence: 'input\\("group_filter"' }],
  service_account_ous: [{ templates: ["ad", "ldap"], evidence: 'area\\("service_account_ous"' }],
  org_url: [{ templates: ["okta"], evidence: 'input\\("org_url"' }],
  tenant_id: [{ templates: ["entra"], evidence: 'input\\("tenant_id"' }],
  cloud: [{ templates: ["entra"], evidence: 'input\\("cloud"' }],
  hybrid: [{ templates: ["entra"], evidence: 'flag\\("hybrid"' }],
  use_dirsync: [{ templates: ["ad"], evidence: 'flag\\("use_dirsync"' }],
  customer: [{ templates: ["google"], evidence: 'input\\("customer"' }],
  domain: [{ templates: ["google"], evidence: 'input\\("domain"' }],
  tenant_host: [{ templates: ["workday"], evidence: 'input\\("tenant_host"' }],
  api_version: [{ templates: ["workday"], evidence: 'input\\("api_version"' }],
  interface: [{ templates: ["workday"], evidence: 'input\\("interface"' }],
  time_zone: [{ templates: ["workday"], evidence: 'input\\("time_zone"' }],
  base_url: [
    { templates: GOVERNED_URL_TEMPLATES, evidence: 'gov\\?\\.baseUrl && input\\("base_url"' },
    { templates: ["scim_app", "salesforce"], evidence: 'input\\("base_url"' },
  ],
  settings: [{ templates: GOVERNED_SETTINGS_TEMPLATES, evidence: 'input\\(`settings\\.\\$\\{f\\.key\\}`' }],
  rest: [{ templates: ["rest_generic"], evidence: 'set\\("rest"\\)' }],
  sql: [{ templates: ["sql"], evidence: 'input\\("sql_engine"' }],
  credential: [{ templates: ["*"], evidence: "saveCredential" }],
  technical_owner: [{ templates: ["*"], evidence: 'input\\("technical_owner"' }],
  business_owner: [{ templates: ["*"], evidence: 'input\\("business_owner"' }],
  correlation_key: [{ templates: ["*"], evidence: 'input\\("correlation_key"' }],
  hr_id_attribute: [{ templates: ["*"], evidence: 'input\\("hr_id_attribute"' }],
  stale_days: [{ templates: ["*"], evidence: 'input\\("stale_days"' }],
  sync_schedule: [{ templates: ["*"], evidence: 'input\\("sync_schedule"' }],
  expected_counts: [{ templates: ["*"], evidence: 'input\\("exp_users"' }],
  write_mode: [{ templates: WRITERS, evidence: 'set\\("write_mode"\\)' }],
  write_scope: [{ templates: WRITERS, evidence: 'area\\("write_scope"' }],
  privileged_expected: [
    { templates: ["ad", "entra", "google", "ibmi", "ldap", "okta", "racf", "rest_generic", "salesforce", "scim_app", "sql"], evidence: 'area\\("privileged"' },
    { templates: PRIVILEGED_GOVERNED, evidence: "PRIVILEGED_GOVERNED" },
  ],
};

/** Fields with no wizard input on purpose, each with the reason. The test fails if one stops being declared by a template. */
export const NOT_AN_INPUT: Record<string, string> = {
  demo_fixed_checks: "set by Apply simulated fix on the Validate step (simulated connections only), never typed",
  role: "a fixed property of the template (authoritative), not connection config",
};
