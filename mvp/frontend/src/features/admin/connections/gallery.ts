// Filter model for the connection type gallery (New connection, step 1). Pure, so `npm test` covers it.

export type Capability = "Identity source" | "Provisioning target" | "HR source" | "Access inventory" | "Contractor source" | "Agent discovery";
export type Category = "Directories & HR" | "Cloud & SaaS" | "Identity providers" | "Databases" | "Cloud & IaaS" | "Source code" | "ERP" | "Privileged access" | "Contractor & VMS" | "AI agents" | "Demo / simulated";

export const CATEGORIES: Category[] = ["Demo / simulated", "Directories & HR", "Cloud & SaaS", "Identity providers", "Databases", "Cloud & IaaS", "Source code", "ERP",
  "Privileged access", "Contractor & VMS", "AI agents"]; // the default selection is a demo type, so it comes first
export const CAPABILITIES: Capability[] = ["Identity source", "Provisioning target", "HR source", "Access inventory", "Contractor source", "Agent discovery"];

export interface GalleryMeta { vendor: string; publisher: string; category: Category; capabilities: Capability[] }

/** Presentation metadata per connector type id; the types themselves stay in CONNECTOR_TYPES. */
export const GALLERY_META: Record<string, GalleryMeta> = {
  "demo-ad": { vendor: "ad", publisher: "Tessera demo", category: "Demo / simulated", capabilities: ["Identity source"] },
  "demo-okta": { vendor: "okta", publisher: "Tessera demo", category: "Demo / simulated", capabilities: ["Identity source"] },
  "demo-workday": { vendor: "workday", publisher: "Tessera demo", category: "Demo / simulated", capabilities: ["HR source"] },
  ad: { vendor: "ad", publisher: "Microsoft", category: "Directories & HR", capabilities: ["Identity source", "Provisioning target"] },
  ldap: { vendor: "ldap", publisher: "OpenLDAP / 389 Directory Server", category: "Directories & HR", capabilities: ["Identity source"] },
  entra: { vendor: "entra", publisher: "Microsoft", category: "Directories & HR", capabilities: ["Identity source", "Provisioning target"] },
  okta: { vendor: "okta", publisher: "Okta", category: "Cloud & SaaS", capabilities: ["Identity source", "Provisioning target"] },
  google: { vendor: "google", publisher: "Google", category: "Cloud & SaaS", capabilities: ["Identity source", "Provisioning target"] },
  workday: { vendor: "workday", publisher: "Workday", category: "Directories & HR", capabilities: ["HR source"] },
  salesforce: { vendor: "salesforce", publisher: "Salesforce", category: "Cloud & SaaS", capabilities: ["Identity source", "Provisioning target"] },
  scim_app: { vendor: "scim_app", publisher: "IETF RFC 7643 / 7644", category: "Cloud & SaaS", capabilities: ["Provisioning target"] },
  sql: { vendor: "sql", publisher: "PostgreSQL, MySQL, SQL Server, Oracle", category: "Databases", capabilities: ["Identity source", "Provisioning target"] },
  "scim:slack": { vendor: "slack", publisher: "Slack", category: "Cloud & SaaS", capabilities: ["Provisioning target"] },
  "scim:zoom": { vendor: "zoom", publisher: "Zoom", category: "Cloud & SaaS", capabilities: ["Provisioning target"] },
  "scim:box": { vendor: "box", publisher: "Box", category: "Cloud & SaaS", capabilities: ["Provisioning target"] },
  "scim:dropbox": { vendor: "dropbox", publisher: "Dropbox", category: "Cloud & SaaS", capabilities: ["Provisioning target"] },
  "scim:zendesk": { vendor: "zendesk", publisher: "Zendesk", category: "Cloud & SaaS", capabilities: ["Provisioning target"] },
  "scim:databricks": { vendor: "databricks", publisher: "Databricks", category: "Cloud & SaaS", capabilities: ["Provisioning target"] },
  "scim:atlassian": { vendor: "atlassian", publisher: "Atlassian", category: "Cloud & SaaS", capabilities: ["Provisioning target"] },
  "scim:pingone": { vendor: "ping", publisher: "Ping Identity", category: "Identity providers", capabilities: ["Provisioning target"] },
  "scim:onelogin": { vendor: "onelogin", publisher: "OneLogin", category: "Identity providers", capabilities: ["Provisioning target"] },
  "scim:jumpcloud": { vendor: "jumpcloud", publisher: "JumpCloud", category: "Identity providers", capabilities: ["Provisioning target"] },
  "scim:keycloak": { vendor: "keycloak", publisher: "Keycloak", category: "Identity providers", capabilities: ["Provisioning target"] },
  "scim:auth0": { vendor: "auth0", publisher: "Auth0", category: "Identity providers", capabilities: ["Provisioning target"] },
  // connectors the server already had, now creatable as governed connections
  awsorg: { vendor: "aws", publisher: "Amazon Web Services", category: "Cloud & IaaS", capabilities: ["Access inventory"] },
  githubscan: { vendor: "github", publisher: "GitHub", category: "Source code", capabilities: ["Agent discovery"] },
  sap: { vendor: "sap", publisher: "SAP", category: "ERP", capabilities: ["Access inventory", "Provisioning target"] },
  oracle: { vendor: "oracle", publisher: "Oracle", category: "ERP", capabilities: ["Access inventory", "Provisioning target"] },
  cyberark: { vendor: "cyberark", publisher: "CyberArk", category: "Privileged access", capabilities: ["Access inventory", "Provisioning target"] },
  beyondtrust: { vendor: "beyondtrust", publisher: "BeyondTrust", category: "Privileged access", capabilities: ["Access inventory", "Provisioning target"] },
  delinea: { vendor: "delinea", publisher: "Delinea", category: "Privileged access", capabilities: ["Access inventory", "Provisioning target"] },
  fieldglass: { vendor: "fieldglass", publisher: "SAP Fieldglass", category: "Contractor & VMS", capabilities: ["Contractor source"] },
  beeline: { vendor: "beeline", publisher: "Beeline", category: "Contractor & VMS", capabilities: ["Contractor source"] },
  csvfeed: { vendor: "csvfeed", publisher: "CSV over HTTPS", category: "Contractor & VMS", capabilities: ["Contractor source"] },
  agentcore: { vendor: "agentcore", publisher: "Amazon Web Services", category: "AI agents", capabilities: ["Agent discovery"] },
  rest_generic: { vendor: "rest_generic", publisher: "Declarative JSON or YAML spec", category: "Cloud & SaaS", capabilities: ["Identity source", "Provisioning target"] },
};

export interface GalleryType { id: string; label: string; blurb: string; demo: boolean }
export interface GalleryFilter { q: string; category: Category | ""; capability: Capability | "" }

export const metaOf = (id: string): GalleryMeta =>
  GALLERY_META[id] ?? { vendor: id, publisher: "", category: "Cloud & SaaS", capabilities: [] };

/** Search matches name, description and publisher; chips narrow by category and capability. */
export function filterGallery<T extends GalleryType>(items: T[], f: GalleryFilter): T[] {
  const q = f.q.trim().toLowerCase();
  return items.filter((t) => {
    const m = metaOf(t.id);
    if (f.category && m.category !== f.category) return false;
    if (f.capability && !m.capabilities.includes(f.capability)) return false;
    return !q || `${t.label} ${t.blurb} ${m.publisher}`.toLowerCase().includes(q);
  });
}

/** Items grouped under their category heading, in CATEGORIES order, empty groups dropped. */
export function groupGallery<T extends GalleryType>(items: T[]): { category: Category; items: T[] }[] {
  return CATEGORIES.map((category) => ({ category, items: items.filter((t) => metaOf(t.id).category === category) }))
    .filter((g) => g.items.length > 0);
}

/** Roving-tabindex target after an arrow/Home/End key; wraps. Returns the current index for other keys. */
export function nextIndex(key: string, i: number, n: number): number {
  if (n === 0) return -1;
  switch (key) {
    case "ArrowRight": case "ArrowDown": return (i + 1) % n;
    case "ArrowLeft": case "ArrowUp": return (i - 1 + n) % n;
    case "Home": return 0;
    case "End": return n - 1;
    default: return i;
  }
}
