import { ReactNode } from "react";
import { siAtlassian, siAuth0, siBox, siDatabricks, siDropbox, siGithub, siGooglecloud, siGoogle, siKeycloak, siLinux, siOkta, siSap, siSnowflake, siZendesk, siZoom } from "simple-icons";

/**
 * A recognizable mark per system on a fixed light "logo plate" (white, subtle border, both themes) so brand colours
 * read on dark mode too. Logos are exempt from WCAG 1.4.3/1.4.11, so brand marks keep their brand colour.
 * Brand marks come from simple-icons (CC0, named imports so only these ship); systems without one get an original
 * generic glyph in its own colour, not vendor artwork.
 */
const BRAND: Record<string, { path: string; hex: string }> = {
  okta: { path: siOkta.path, hex: siOkta.hex },
  google: { path: siGoogle.path, hex: siGoogle.hex },
  github: { path: siGithub.path, hex: siGithub.hex },
  snowflake: { path: siSnowflake.path, hex: siSnowflake.hex },
  zoom: { path: siZoom.path, hex: siZoom.hex },
  box: { path: siBox.path, hex: siBox.hex },
  dropbox: { path: siDropbox.path, hex: siDropbox.hex },
  zendesk: { path: siZendesk.path, hex: siZendesk.hex },
  databricks: { path: siDatabricks.path, hex: siDatabricks.hex },
  atlassian: { path: siAtlassian.path, hex: siAtlassian.hex },
  auth0: { path: siAuth0.path, hex: siAuth0.hex },
  keycloak: { path: siKeycloak.path, hex: siKeycloak.hex },
  sap: { path: siSap.path, hex: siSap.hex },
  gcp: { path: siGooglecloud.path, hex: siGooglecloud.hex },
  linux: { path: siLinux.path, hex: siLinux.hex },
};

const stroke = { fill: "none", strokeWidth: 1.7, strokeLinecap: "round", strokeLinejoin: "round" } as const;

// Generic glyphs on a 24x24 grid, each with its own colour (all legible on the white plate).
const GENERIC: Record<string, { color: string; glyph: ReactNode }> = {
  // directory tree
  ad: { color: "#0f6cbd", glyph: <g {...stroke} stroke="#0f6cbd"><rect x="9" y="2.5" width="6" height="4.5" rx="1" /><rect x="2.5" y="16.5" width="6" height="4.5" rx="1" /><rect x="15.5" y="16.5" width="6" height="4.5" rx="1" /><path d="M12 7v4.5M5.5 16.5v-5h13v5" /></g> },
  // root with a list of entries
  ldap: { color: "#0e7a7a", glyph: <g {...stroke} stroke="#0e7a7a"><circle cx="5" cy="5" r="2" /><path d="M5 7v12M5 12h5M5 19h5" /><rect x="11" y="9.5" width="9" height="5" rx="1" /><rect x="11" y="16.5" width="9" height="5" rx="1" /></g> },
  // identity shield with a person
  entra: { color: "#5b4bc4", glyph: <g {...stroke} stroke="#5b4bc4"><path d="M12 2.5l8 3v6c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10v-6z" /><circle cx="12" cy="10" r="2.5" /><path d="M7.5 17c.8-2.4 2.6-3.5 4.5-3.5s3.7 1.1 4.5 3.5" /></g> },
  // org chart: HR source
  workday: { color: "#c75000", glyph: <g {...stroke} stroke="#c75000"><circle cx="12" cy="5" r="2.5" /><circle cx="5" cy="19" r="2.5" /><circle cx="19" cy="19" r="2.5" /><path d="M12 7.5v4M5 16.5v-5h14v5" /></g> },
  // cloud with a stack of accounts (no simple-icons mark for AWS)
  aws: { color: "#b45309", glyph: <g {...stroke} stroke="#b45309"><path d="M7 18a4 4 0 01-.6-7.95A5.5 5.5 0 0117 9.5a4.2 4.2 0 01.5 8.5z" /><path d="M9 21h6" /></g> },
  // cloud with a person (SaaS CRM)
  salesforce: { color: "#0b6fa8", glyph: <g {...stroke} stroke="#0b6fa8"><path d="M7 19a4 4 0 01-.6-7.95A5.5 5.5 0 0117 10.5a4.2 4.2 0 01.5 8.5z" /></g> },
  // service ticket with a notch and a dotted tear line (no simple-icons mark for ServiceNow in 16.30.0: an original glyph, not vendor artwork)
  servicenow: { color: "#1b6b3a", glyph: <g {...stroke} stroke="#1b6b3a"><path d="M4 6.5h16v3.2a2.3 2.3 0 000 4.6v3.2H4v-3.2a2.3 2.3 0 000-4.6z" /><path d="M14.5 6.5v1.6M14.5 11v2M14.5 15.9v1.6" /><path d="M7.5 10.5h4M7.5 13.5h3" /></g> },
  // cloud over a grid of role tiles (no simple-icons mark for Azure in 16.30.0: an original glyph, not vendor artwork)
  azure: { color: "#0f6cbd", glyph: <g {...stroke} stroke="#0f6cbd"><path d="M7 14a4 4 0 01-.6-7.95A5.5 5.5 0 0117 5.5a4.2 4.2 0 01.5 8.5" /><rect x="6" y="16" width="4" height="4" rx=".8" /><rect x="14" y="16" width="4" height="4" rx=".8" /><path d="M10 18h4M12 14v2" /></g> },
  // database cylinder (no single vendor: PostgreSQL, MySQL, SQL Server and Oracle share this tile)
  sql: { color: "#1d5f8a", glyph: <g {...stroke} stroke="#1d5f8a"><ellipse cx="12" cy="5.5" rx="7.5" ry="3" /><path d="M4.5 5.5v13c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-13M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3" /></g> },
  // no simple-icons mark in 16.30.0 for these four: original glyphs, not vendor artwork
  // speech bubble (chat workspace)
  slack: { color: "#611f69", glyph: <g {...stroke} stroke="#611f69"><path d="M4 5.5h16v10H11l-4.5 4v-4H4z" /><path d="M8 9.5h8M8 12.5h5" /></g> },
  // key (identity provider with a login)
  ping: { color: "#b3282d", glyph: <g {...stroke} stroke="#b3282d"><circle cx="8" cy="12" r="4" /><path d="M12 12h9M18 12v3.5M21 12v2.5" /></g> },
  // person in a circle (single sign-on portal)
  onelogin: { color: "#1d4ed8", glyph: <g {...stroke} stroke="#1d4ed8"><circle cx="12" cy="12" r="9" /><circle cx="12" cy="10" r="2.5" /><path d="M7.5 17c.8-2.4 2.6-3.5 4.5-3.5s3.7 1.1 4.5 3.5" /></g> },
  // cloud with a lock (cloud directory)
  jumpcloud: { color: "#0f766e", glyph: <g {...stroke} stroke="#0f766e"><path d="M7 18a4 4 0 01-.6-7.95A5.5 5.5 0 0117 9.5a4.2 4.2 0 01.5 8.5z" /><rect x="9.5" y="12" width="5" height="4" rx=".8" /></g> },
  // database cylinder (no simple-icons mark for Oracle)
  oracle: { color: "#b3261e", glyph: <g {...stroke} stroke="#b3261e"><ellipse cx="12" cy="6" rx="7" ry="3" /><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3" /></g> },
  // vault door with a dial
  cyberark: { color: "#0b5cad", glyph: <g {...stroke} stroke="#0b5cad"><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="12" cy="12" r="3.5" /><path d="M12 8.5V6M12 18v-2.5M8.5 12H6M18 12h-2.5" /></g> },
  // shield with a key
  beyondtrust: { color: "#b83c0c", glyph: <g {...stroke} stroke="#b83c0c"><path d="M12 2.5l8 3v6c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10v-6z" /><circle cx="10" cy="11" r="2" /><path d="M12 11h4.5M15 11v2.5" /></g> },
  // padlock
  delinea: { color: "#0a6e78", glyph: <g {...stroke} stroke="#0a6e78"><rect x="5" y="10.5" width="14" height="10" rx="2" /><path d="M8 10.5V8a4 4 0 018 0v2.5" /><circle cx="12" cy="15.5" r="1.3" /></g> },
  // contractor ID badge
  fieldglass: { color: "#1d6a3a", glyph: <g {...stroke} stroke="#1d6a3a"><rect x="4" y="3.5" width="16" height="17" rx="2" /><circle cx="12" cy="10" r="2.5" /><path d="M7.5 17c.8-2.2 2.6-3 4.5-3s3.7.8 4.5 3" /></g> },
  // hexagon with assignment lines
  beeline: { color: "#8a5a00", glyph: <g {...stroke} stroke="#8a5a00"><path d="M12 2.5l8 4.5v10l-8 4.5-8-4.5V7z" /><path d="M8 11.5h8M8 15h5" /></g> },
  // table grid: a CSV feed
  csvfeed: { color: "#3f4a5a", glyph: <g {...stroke} stroke="#3f4a5a"><rect x="3.5" y="4.5" width="17" height="15" rx="1.5" /><path d="M3.5 9.5h17M3.5 14.5h17M9.5 4.5v15" /></g> },
  // agent: a robot head
  agentcore: { color: "#6d28d9", glyph: <g {...stroke} stroke="#6d28d9"><rect x="5" y="8" width="14" height="10" rx="2.5" /><circle cx="9.5" cy="13" r="1.2" /><circle cx="14.5" cy="13" r="1.2" /><path d="M12 8V5M10 5h4M3 12v2M21 12v2" /></g> },
  // a plug into a socket: the Model Context Protocol connects tools to agents
  mcp: { color: "#0f766e", glyph: <g {...stroke} stroke="#0f766e"><path d="M9 3v4M15 3v4M6.5 7h11v4a5.5 5.5 0 01-11 0zM12 16.5V21" /></g> },
  // a robot head over a cloud shelf: an agent on Amazon Bedrock
  bedrock: { color: "#c2410c", glyph: <g {...stroke} stroke="#c2410c"><rect x="6" y="4" width="12" height="9" rx="2.5" /><circle cx="10" cy="8.5" r="1.1" /><circle cx="14" cy="8.5" r="1.1" /><path d="M12 4V2M4 20h16M7 16.5h10" /></g> },
  // a robot head over a diamond: an agent on Google Vertex AI
  vertex: { color: "#1a73e8", glyph: <g {...stroke} stroke="#1a73e8"><rect x="6" y="3.5" width="12" height="8.5" rx="2.5" /><circle cx="10" cy="7.8" r="1.1" /><circle cx="14" cy="7.8" r="1.1" /><path d="M12 15l4 3.5-4 3-4-3z" /></g> },
  // a robot head over a hexagon: an agent in Azure AI Foundry
  foundry: { color: "#0078d4", glyph: <g {...stroke} stroke="#0078d4"><rect x="6" y="3.5" width="12" height="8.5" rx="2.5" /><circle cx="10" cy="7.8" r="1.1" /><circle cx="14" cy="7.8" r="1.1" /><path d="M9 15.5h6l2 3-2 3H9l-2-3z" /></g> },
  // a speech bubble with a spark: a Copilot Studio agent
  copilot: { color: "#117865", glyph: <g {...stroke} stroke="#117865"><path d="M5 5.5h14v10H11l-4 3.5v-3.5H5z" /><path d="M12 8v4M10 10h4" /></g> },
  // a robot head with a halo: a Salesforce Agentforce agent
  agentforce: { color: "#0b6fa8", glyph: <g {...stroke} stroke="#0b6fa8"><rect x="5.5" y="8.5" width="13" height="10" rx="2.5" /><circle cx="9.5" cy="13.5" r="1.1" /><circle cx="14.5" cy="13.5" r="1.1" /><path d="M8 5.5a5 2 0 018 0" /></g> },
  // curly braces around a request arrow: a JSON API described by a spec
  rest_generic: { color: "#7c3aed", glyph: <g {...stroke} stroke="#7c3aed"><path d="M8 3.5C6 3.5 5.5 4.6 5.5 6.2v2.1c0 1.2-.7 2.2-2 2.7 1.3.5 2 1.5 2 2.7v2.1c0 1.6.5 2.7 2.5 2.7M16 3.5c2 0 2.5 1.1 2.5 2.7v2.1c0 1.2.7 2.2 2 2.7-1.3.5-2 1.5-2 2.7v2.1c0 1.6-.5 2.7-2.5 2.7" /><path d="M9.5 12h5M12.5 9.5l2.5 2.5-2.5 2.5" /></g> },
  // protocol glyph: two-way arrows
  scim_app: { color: "#475569", glyph: <g {...stroke} stroke="#475569"><path d="M4 8h14M14 4l4 4-4 4M20 16H6M10 12l-4 4 4 4" /></g> },
};

/** `label` gives the logo an accessible name; without it the logo is decorative (the caller names the system). */
export function VendorLogo({ vendor, label, size = 56 }: { vendor: string; label?: string; size?: number }) {
  const brand = BRAND[vendor];
  const generic = GENERIC[vendor] ?? GENERIC.scim_app;
  const a11y = label ? { role: "img", "aria-label": label } : { "aria-hidden": true as const };
  return (
    <span className="vendor-plate" style={{ width: size, height: size }} {...a11y}>
      <svg viewBox="0 0 24 24" width={Math.round(size * 0.6)} height={Math.round(size * 0.6)} focusable={false} aria-hidden>
        {brand ? <path d={brand.path} fill={`#${brand.hex}`} /> : generic.glyph}
      </svg>
    </span>
  );
}

// Connector type and system names that share another system's mark.
const ALIAS: Record<string, string> = { awsorg: "aws", azurerbac: "azure", gcpiam: "gcp", unixssh: "linux", unix: "linux", githubscan: "github", "github-scan": "github", "aws-agentcore": "agentcore", csv: "csvfeed", successfactors: "sap" };

/** The logo vendor for a connection: the first id that has a mark ("demo-okta" is Okta), else the generic protocol glyph. */
export function vendorForType(...ids: string[]): string {
  for (const id of ids) {
    const t0 = id.replace(/^demo-/, "");
    const t = ALIAS[t0] ?? t0;
    if (t !== "scim_app" && (t in BRAND || t in GENERIC)) return t;
  }
  return "scim_app";
}
