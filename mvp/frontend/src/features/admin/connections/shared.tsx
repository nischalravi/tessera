/** Shared bits of the connection setup screens (design §10). */
import { ReactNode, useState } from "react";
import { Link } from "react-router-dom";
import { Band, Blocker, GateReport, RevisionState, isGateReport } from "../../../api";
import { Badge, Bar, Callout, Tone, useToast } from "../../../components";

export const STATE_LABEL: Record<RevisionState | "legacy", string> = {
  draft: "Draft", ready_to_validate: "Ready to validate", validated: "Validated", dry_run_reconciled: "Dry run reconciled",
  active: "Active", degraded: "Degraded", retired: "Retired", superseded: "Superseded", legacy: "Legacy (env)",
};
const STATE_TONE: Record<string, Tone> = {
  draft: "outline", ready_to_validate: "info", validated: "info", dry_run_reconciled: "accent", active: "ok", degraded: "warning",
  retired: "neutral", superseded: "neutral", legacy: "neutral",
};
export function StateBadge({ state }: { state: RevisionState | "legacy" }) {
  return <Badge tone={STATE_TONE[state] ?? "neutral"} dot>{STATE_LABEL[state] ?? state}</Badge>;
}

export const BAND_LABEL: Record<Band, string> = { healthy: "Healthy", needs_attention: "Needs attention", at_risk: "At risk", not_ready: "Not ready" };
export const bandTone = (b: Band | ""): Tone => (b === "healthy" ? "ok" : b === "needs_attention" ? "warning" : b ? "critical" : "neutral");

/** Score as a bar with the number and the band text (never colour alone). */
export function ScoreCell({ score, band }: { score: number | null | undefined; band?: Band | "" }) {
  if (score === null || score === undefined) return <span className="faint small">No score yet</span>;
  return (
    <div className="score-cell">
      <span className="tnum"><b>{score}</b></span>
      <Bar value={score} tone={score >= 70 ? "ok" : "risk"} />
      {band && <span className="small faint">{BAND_LABEL[band]}</span>}
    </div>
  );
}

export function SimulatedBadge({ scenario }: { scenario?: string }) {
  return (
    <Badge tone="info" title={`Simulated: results come from the demo scenario${scenario ? ` "${scenario}"` : ""}, not a live directory. Simulated results can never activate a real connector type.`}>
      Simulated
    </Badge>
  );
}

/** The blockers of a gate, as the server returned them. */
export function BlockerList({ blocking, connectionId, empty }: { blocking: Blocker[]; connectionId: string; empty?: ReactNode }) {
  if (!blocking.length) return <>{empty ?? null}</>;
  return (
    <ul className="blockers" aria-label="What blocks this step">
      {blocking.map((b, i) => (
        <li key={i}>
          {b.item ? (
            b.item.includes(".") && !b.item.startsWith("config.") ? (
              <Link to={`/admin/connections/${connectionId}?item=${b.item}`}><code>{b.item}</code></Link>
            ) : <code>{b.item}</code>
          ) : <code>{b.finding}</code>}{" "}
          {(b.level || b.severity) && <Badge tone={b.severity === "critical" || b.level === "required" ? "critical" : "warning"}>{b.severity ?? b.level}</Badge>}{" "}
          <span className="faint">{b.status}</span>: {b.reason}
        </li>
      ))}
    </ul>
  );
}

/** Runs a readiness action, toasting success; a refused gate returns its report. */
export function useAction() {
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const [report, setReport] = useState<GateReport | null>(null);
  const run = async <T,>(key: string, fn: () => Promise<T>, ok?: (r: T) => ReactNode): Promise<T | null> => {
    setBusy(key);
    setReport(null);
    try {
      const r = await fn();
      if (ok) toast(ok(r));
      return r;
    } catch (e) {
      if (isGateReport(e)) {
        setReport(e.body);
        toast(`${e.body.blocking.length} item${e.body.blocking.length === 1 ? "" : "s"} block this step`, { kind: "error" });
      } else {
        toast((e as Error).message, { kind: "error" });
      }
      return null;
    } finally {
      setBusy(null);
    }
  };
  return { busy, report, setReport, run };
}

export function GateCallout({ report, connectionId }: { report: GateReport | null; connectionId: string }) {
  if (!report) return null;
  return (
    <Callout tone="bad">
      <b>The server refused the step ({report.error ?? "blocked"}).</b> The revision is {STATE_LABEL[report.state as RevisionState] ?? report.state}.
      <BlockerList blocking={report.blocking} connectionId={connectionId} />
    </Callout>
  );
}

/** Observed values as "key: value" text (counts, versions, dates; never secrets). */
export function observedText(o: Record<string, unknown>) {
  return Object.entries(o)
    .filter(([k]) => k !== "simulated_fix_available")
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

export const CONNECTOR_TYPES: { id: string; label: string; template: string; demo: boolean; blurb: string }[] = [
  { id: "demo-ad", label: "Active Directory (demo)", template: "ad", demo: true, blurb: "Simulated forest built from the demo company, with planted gaps." },
  { id: "demo-okta", label: "Okta (demo)", template: "okta", demo: true, blurb: "The demo Okta org, including the leaver the legacy process missed." },
  { id: "demo-workday", label: "Workday (demo)", template: "workday", demo: true, blurb: "The demo HR source, as the authoritative connection." },
  { id: "ad", label: "Active Directory", template: "ad", demo: false, blurb: "Through the Directory Agent (DR-11, DR-12)." },
  { id: "ldap", label: "OpenLDAP / 389-DS", template: "ldap", demo: false, blurb: "Generic LDAP (DR-13)." },
  { id: "entra", label: "Microsoft Entra ID", template: "entra", demo: false, blurb: "Microsoft Graph (DR-14)." },
  { id: "okta", label: "Okta", template: "okta", demo: false, blurb: "OAuth service app (DR-15)." },
  { id: "google", label: "Google Workspace", template: "google", demo: false, blurb: "Domain-wide delegation (DR-16)." },
  { id: "workday", label: "Workday", template: "workday", demo: false, blurb: "Integration system user (DR-17)." },
  { id: "salesforce", label: "Salesforce", template: "salesforce", demo: false, blurb: "Users, profiles, permission sets and groups; OAuth JWT bearer." },
  { id: "scim_app", label: "SCIM 2.0 application", template: "scim_app", demo: false, blurb: "Any SCIM service (DR-18)." },
  { id: "sql", label: "Database (SQL)", template: "sql", demo: false, blurb: "PostgreSQL, MySQL, SQL Server or Oracle: database accounts and roles, or an application's own tables." },
  { id: "scim:slack", label: "Slack", template: "scim_app", demo: false, blurb: "SCIM needs a Business+ or Enterprise plan." },
  { id: "scim:zoom", label: "Zoom", template: "scim_app", demo: false, blurb: "SCIM 2.0 preset." },
  { id: "scim:box", label: "Box", template: "scim_app", demo: false, blurb: "SCIM 2.0 preset." },
  { id: "scim:dropbox", label: "Dropbox", template: "scim_app", demo: false, blurb: "SCIM 2.0 preset." },
  { id: "scim:zendesk", label: "Zendesk", template: "scim_app", demo: false, blurb: "SCIM 2.0 preset." },
  { id: "scim:databricks", label: "Databricks", template: "scim_app", demo: false, blurb: "Needs the Premium plan or above." },
  { id: "scim:atlassian", label: "Atlassian Cloud", template: "scim_app", demo: false, blurb: "Directory API key from Atlassian Administration." },
  { id: "scim:pingone", label: "PingOne", template: "scim_app", demo: false, blurb: "SCIM 2.0 preset." },
  { id: "scim:onelogin", label: "OneLogin", template: "scim_app", demo: false, blurb: "SCIM 2.0 preset." },
  { id: "scim:jumpcloud", label: "JumpCloud", template: "scim_app", demo: false, blurb: "SCIM 2.0 preset." },
  { id: "scim:keycloak", label: "Keycloak (SCIM extension)", template: "scim_app", demo: false, blurb: "Needs a SCIM extension installed." },
  { id: "scim:auth0", label: "Auth0", template: "scim_app", demo: false, blurb: "Needs a plan with Enterprise Connections." },
  { id: "awsorg", label: "AWS Organizations and IAM", template: "awsorg", demo: false, blurb: "Reader role in each account through sts:AssumeRole; feeds the effective-permission analysis." },
  { id: "azurerbac", label: "Azure RBAC", template: "azurerbac", demo: false, blurb: "Role assignments, role definitions and PIM eligible assignments of subscriptions and management groups, read-only." },
  { id: "gcpiam", label: "Google Cloud IAM", template: "gcpiam", demo: false, blurb: "IAM policies of an organization, folders and projects, their roles and service accounts, read-only." },
  { id: "githubscan", label: "GitHub (code scan)", template: "githubscan", demo: false, blurb: "Reads MCP configuration and agent credentials from an organization's repositories, read-only." },
  { id: "sap", label: "SAP", template: "erp", demo: false, blurb: "Roles, transaction codes and authorization objects as fine-grained access." },
  { id: "oracle", label: "Oracle Fusion Applications", template: "erp", demo: false, blurb: "Roles and privileges of Oracle Fusion as fine-grained access." },
  { id: "cyberark", label: "CyberArk Privileged Access Manager", template: "pam", demo: false, blurb: "Safes, their members and vaulted accounts; safe membership through provisioning." },
  { id: "beyondtrust", label: "BeyondTrust Password Safe", template: "pam", demo: false, blurb: "Smart rules, user groups and managed accounts; membership through provisioning." },
  { id: "delinea", label: "Delinea Secret Server", template: "pam", demo: false, blurb: "Folders, their permissions and secrets; membership through provisioning." },
  { id: "fieldglass", label: "SAP Fieldglass", template: "vms", demo: false, blurb: "Contractor assignments with a sponsor and an end date." },
  { id: "beeline", label: "Beeline", template: "vms", demo: false, blurb: "Contractor assignments with a sponsor and an end date." },
  { id: "csvfeed", label: "Contractor CSV feed", template: "vms", demo: false, blurb: "A contractor file fetched over HTTPS (uploads stay on the Contractors page)." },
  { id: "agentcore", label: "AWS Bedrock AgentCore", template: "agentcore", demo: false, blurb: "Agent runtimes from a recorded snapshot; no live client yet, refused in prod." },
  { id: "rest_generic", label: "Generic REST API", template: "rest_generic", demo: false, blurb: "Any HTTP/JSON system, mapped by a declarative spec, no code (issue #552)." },
];
