import { Link, useNavigate } from "react-router-dom";
import { IdentityBrief, useApi } from "../../api";
import { Bar, Kpi, Loading, Page, TypeBadge } from "../../components";

export interface Summary {
  identities: { human: number; service: number; ai_agent: number; terminated: number };
  accounts: number;
  systems: number;
  grants: number;
  effective_permissions: number;
  unused_permissions: number;
  unused_pct: number;
  violations: { total: number; by_severity: Record<string, number>; by_policy: Record<string, number> };
  nhi: { orphaned: number; stale_secrets: number; agents_with_pii: number };
  jit: { pending: number; active: number };
  reviews: { open_items: number };
  recommendations: { total: number; remove: number; role_trim: number };
  hris_pending: number;
  top_risky: (IdentityBrief & { effective: number; unused: number; privileged: number; violations: number; risk: number })[];
  usage_trend: { day: string; events: number }[];
}

function Trend({ points }: { points: { day: string; events: number }[] }) {
  if (!points.length) return null;
  const w = 600, h = 120, max = Math.max(...points.map((p) => p.events), 1);
  const xs = (i: number) => (i / Math.max(1, points.length - 1)) * w;
  const ys = (v: number) => h - (v / max) * (h - 10) - 2;
  const d = points.map((p, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(p.events).toFixed(1)}`).join(" ");
  const total = points.reduce((a, p) => a + p.events, 0);
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" role="img" aria-label={`Daily permission usage over ${points.length} days, ${total.toLocaleString()} events in total`}>
      <path d={`${d} L${w},${h} L0,${h} Z`} fill="var(--accent-soft)" />
      <path d={d} fill="none" stroke="var(--accent)" strokeWidth="2" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** KPI row shared with the Admin & security Home. */
export function RiskKpis({ d }: { d: Summary }) {
  const sev = d.violations.by_severity;
  return (
    <div className="grid g4">
      <Kpi label="Identities" value={d.identities.human + d.identities.service + d.identities.ai_agent} sub={`${d.identities.human} people · ${d.identities.service} service · ${d.identities.ai_agent} AI agents`} to="/directory/people" />
      <Kpi label="Unused permissions (60 days)" value={`${d.unused_pct}%`} sub={`${d.unused_permissions} of ${d.effective_permissions} · ${d.recommendations.remove} safe to remove`} to="/insights/least-privilege" />
      <Kpi label="Policy violations" tone="critical" value={d.violations.total} sub={`${sev.critical ?? 0} critical · ${sev.high ?? 0} high · ${sev.medium ?? 0} medium`} to="/governance/policies" />
      <Kpi label="Machine identity risk" tone="warning" value={d.nhi.orphaned} sub={`without a current owner · ${d.nhi.stale_secrets} stale secrets · ${d.nhi.agents_with_pii} agents on PII`} to="/directory/machine" />
    </div>
  );
}

export function RiskyTable({ rows }: { rows: Summary["top_risky"] }) {
  const nav = useNavigate();
  return (
    <div className="table-scroll">
      <table>
        <thead><tr><th>Identity</th><th className="hide-narrow">Type</th><th className="num hide-narrow">Permissions</th><th className="num">Unused</th><th className="num hide-narrow">Privileged</th><th className="num">Violations</th><th>Risk</th></tr></thead>
        <tbody>
          {rows.map((i) => (
            <tr key={i.id} className="click" tabIndex={0} onClick={() => nav(`/directory/identities/${i.id}`)} onKeyDown={(e) => e.key === "Enter" && nav(`/directory/identities/${i.id}`)}>
              <td><b>{i.name}</b><div className="xs faint">{i.title ?? i.department}</div></td>
              <td className="hide-narrow"><TypeBadge type={i.type} /></td>
              <td className="num hide-narrow">{i.effective}</td>
              <td className="num">{i.unused}</td>
              <td className="num hide-narrow">{i.privileged}</td>
              <td className="num">{i.violations}</td>
              <td style={{ width: 110 }}><Bar value={i.risk} tone="risk" /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function RiskOverview() {
  const { data: d, error } = useApi<Summary>("/summary");
  const crumbs: [string, string?][] = [["Insights", "/insights"], ["Risk overview"]];
  if (!d) return <Page title="Risk overview" crumbs={crumbs}><Loading error={error} kind="page" /></Page>;
  const policies = Object.entries(d.violations.by_policy).sort((a, b) => b[1] - a[1]);
  const maxPol = Math.max(...policies.map((p) => p[1]), 1);
  return (
    <Page title="Risk overview" crumbs={crumbs} sub="Effective access across every person, service account and AI agent, computed from the identity graph and 90 days of usage.">
      <RiskKpis d={d} />
      <div className="grid g4 mt">
        <Kpi label="Approvals waiting" value={d.jit.pending} sub={`${d.jit.active} active elevations`} to="/inbox?filter=approval" />
        <Kpi label="Review items open" value={d.reviews.open_items} sub="exception-only campaigns" to="/governance/reviews" />
        <Kpi label="Lifecycle tasks" value={d.hris_pending} sub="joiner, mover, leaver" to="/governance/lifecycle" />
        <Kpi label="Accounts" value={d.accounts} sub={`across ${d.systems} systems · ${d.grants} grants`} to="/directory/accounts" />
      </div>
      <div className="grid g21 mt">
        <div className="card flush">
          <div className="card-h"><h2>Riskiest identities</h2><Link to="/directory/people" className="small">All people</Link></div>
          <RiskyTable rows={d.top_risky} />
        </div>
        <div className="card stack-sm">
          <h2>Violations by policy</h2>
          {policies.map(([name, n]) => (
            <div key={name}>
              <div className="spread small"><Link to="/governance/policies">{name}</Link><b className="tnum">{n}</b></div>
              <Bar value={n} max={maxPol} />
            </div>
          ))}
        </div>
      </div>
      <div className="card mt">
        <div className="spread"><h2>Permission usage, last 90 days</h2><span className="xs faint">Daily events from connector audit logs</span></div>
        <Trend points={d.usage_trend} />
      </div>
    </Page>
  );
}
