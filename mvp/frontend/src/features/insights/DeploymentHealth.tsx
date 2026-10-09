/**
 * Deployment health (Preview): is this tenant set up well enough to trust its numbers?
 * Checks marked "live" are computed from the real API (connectors, accounts, policies, summary);
 * the rest describe settings that have no backend yet.
 */
import { Link } from "react-router-dom";
import { CircleAlert, CircleCheck, TriangleAlert } from "lucide-react";
import { AccountRow, ConnectorRow, Policy, useApi } from "../../api";
import { Badge, Bar, InsightsTabs, Loading, Page, PreviewBadge } from "../../components";
import type { Summary } from "./RiskOverview";

export interface Check {
  id: string;
  title: string;
  detail: string;
  status: "ok" | "warn" | "crit";
  required: boolean;
  live: boolean;
  to?: string;
}

export function useHealthChecks(): { checks: Check[] | null; score: number | null } {
  const { data: conns } = useApi<ConnectorRow[]>("/connectors");
  const { data: accounts } = useApi<AccountRow[]>("/accounts");
  const { data: policies } = useApi<Policy[]>("/policies");
  const { data: summary } = useApi<Summary>("/summary");
  if (!conns || !accounts || !policies || !summary) return { checks: null, score: null };
  const checks: Check[] = [];
  const has = (s: string) => conns.some((c) => c.system === s);
  checks.push({
    id: "hr", title: has("workday") ? "Workday is the authoritative HR source" : "No HR source connected", live: true, required: true,
    detail: has("workday") ? "Joiners, movers and leavers come from Workday and drive birthright access." : "Without an HR source, Tessera can't detect leavers.", status: has("workday") ? "ok" : "crit", to: "/admin/connections",
  });
  for (const c of conns) {
    const orphan = accounts.filter((a) => a.system === c.system && !a.identity).length;
    checks.push({
      id: `corr-${c.system}`, live: true, required: true, to: `/directory/accounts`,
      title: orphan ? `${c.name}: ${orphan} account${orphan === 1 ? "" : "s"} can't be matched to an identity` : `${c.name}: every account is correlated`,
      detail: orphan ? "Correlate them by external ID or email in Identity rules, or disable them." : `${c.accounts} accounts, ${c.groups} groups and roles, ${c.permissions} permissions synced.`,
      status: orphan ? "warn" : "ok",
    });
  }
  checks.push({
    id: "owners", live: true, required: true, to: "/directory/machine",
    title: summary.nhi.orphaned ? `${summary.nhi.orphaned} machine identities have no live owner` : "Every machine identity has an owner",
    detail: "Each service account and AI agent needs an accountable human owner.", status: summary.nhi.orphaned ? "crit" : "ok",
  });
  checks.push({
    id: "secrets", live: true, required: false, to: "/directory/machine",
    title: summary.nhi.stale_secrets ? `${summary.nhi.stale_secrets} secrets are older than 90 days` : "No stale secrets",
    detail: "Rotate long-lived keys or move them to short-lived credentials.", status: summary.nhi.stale_secrets ? "warn" : "ok",
  });
  checks.push({
    id: "policies", live: true, required: true, to: "/governance/policies",
    title: `${policies.filter((p) => p.enabled).length} policies are evaluated on every change`, detail: "Policies are YAML in Git and re-run against the effective-permission graph.", status: policies.length ? "ok" : "warn",
  });
  checks.push({ id: "sso", live: false, required: true, to: "/admin/authentication", title: "Sign-in to Tessera is not configured", detail: "Configure SAML or OIDC so approvals are recorded against real users, not the demo persona.", status: "warn" });
  checks.push({ id: "notify", live: false, required: false, to: "/admin/notifications", title: "Notifications are not configured", detail: "Approvers and reviewers only see work in the Inbox until email or chat is set up.", status: "warn" });
  checks.push({ id: "jobs", live: false, required: false, to: "/admin/jobs", title: "Connector syncs run on demand", detail: "Schedule full and delta syncs so the graph stays current.", status: "warn" });
  const req = checks.filter((c) => c.status !== "ok" && c.required).length;
  const rec = checks.filter((c) => c.status !== "ok" && !c.required).length;
  return { checks, score: Math.max(0, 100 - 6 * req - 2 * rec) };
}

const ICON = { ok: <CircleCheck size={18} color="var(--ok)" aria-label="Passing" />, warn: <TriangleAlert size={18} color="var(--warning)" aria-label="Needs attention" />, crit: <CircleAlert size={18} color="var(--critical)" aria-label="Failing" /> };

export function HealthChecks() {
  const { checks, score } = useHealthChecks();
  if (!checks || score === null) return <div className="card"><Loading kind="block" /></div>;
  const failing = checks.filter((c) => c.status !== "ok");
  const required = failing.filter((c) => c.required).length;
  const order = { crit: 0, warn: 1, ok: 2 };
  return (
    <div className="grid g21">
      <div className="card">
        <div className="spread" style={{ marginBottom: 4 }}>
          <h2>Checks</h2>
          <span className="small faint">{failing.length} need attention · {checks.length - failing.length} passing</span>
        </div>
        {[...checks].sort((a, b) => order[a.status] - order[b.status]).map((c) => (
          <div key={c.id} className="check-row">
            {ICON[c.status]}
            <div style={{ minWidth: 0 }}>
              <div className="row tight"><b>{c.title}</b>{c.required && c.status !== "ok" && <Badge tone={c.status === "crit" ? "critical" : "warning"}>Required</Badge>}{!c.live && <PreviewBadge what="This check describes a setting that has no backend yet." />}</div>
              <div className="small faint">{c.detail}</div>
            </div>
            {c.to && c.status !== "ok" ? <Link className="btn sm" to={c.to}>Fix</Link> : <span />}
          </div>
        ))}
      </div>
      <div className="card stack-sm" style={{ alignSelf: "start" }}>
        <h2>Readiness</h2>
        <div className="kpi" style={{ padding: 0 }}><div className="value">{score} <span className="faint" style={{ fontSize: "var(--fs-lg)" }}>/ 100</span></div></div>
        <Bar value={score} tone="ok" />
        <p className="small muted">{required ? `${required} required item${required === 1 ? "" : "s"} before go-live.` : "No required items left."} Required items lower the score by 6 points, recommended ones by 2.</p>
      </div>
    </div>
  );
}

export function DeploymentHealth() {
  return (
    <Page title="Deployment health" crumbs={[["Protection"], ["Insights", "/insights"], ["Deployment health"]]} tabs={<InsightsTabs />} badge={<PreviewBadge what="Partly computed from live data, partly describing settings that have no backend yet." />} sub="Whether this tenant is connected and configured well enough to trust its risk numbers.">
      <HealthChecks />
    </Page>
  );
}
