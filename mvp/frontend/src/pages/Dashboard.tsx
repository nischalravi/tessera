import { Link, useNavigate } from "react-router-dom";
import { useApi } from "../api";
import { Bar, Loading, Page, TypeBadge } from "../components/ui";

function Trend({ points }: { points: { day: string; events: number }[] }) {
  if (!points.length) return null;
  const w = 600, h = 120, max = Math.max(...points.map((p) => p.events));
  const xs = (i: number) => (i / Math.max(1, points.length - 1)) * w;
  const ys = (v: number) => h - (v / max) * (h - 10) - 2;
  const d = points.map((p, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(p.events).toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" role="img" aria-label="Daily permission usage events">
      <path d={`${d} L${w},${h} L0,${h} Z`} fill="#eef2ff" />
      <path d={d} fill="none" stroke="#4f46e5" strokeWidth="2" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export default function Dashboard() {
  const { data: d, error } = useApi<any>("/summary");
  const nav = useNavigate();
  if (!d) return <Loading error={error} />;
  const sev = d.violations.by_severity;
  const policies = Object.entries(d.violations.by_policy as Record<string, number>).sort((a, b) => b[1] - a[1]);
  const maxPol = Math.max(...policies.map((p) => p[1]), 1);
  return (
    <Page title="Identity risk overview" sub="Effective access across every human, service account and AI agent — computed from the identity graph and 90 days of usage.">
      <div className="grid g4">
        <div className="card kpi">
          <div className="label">Identities</div>
          <div className="value">{d.identities.human + d.identities.service + d.identities.ai_agent}</div>
          <div className="sub">{d.identities.human} human · {d.identities.service} service · {d.identities.ai_agent} AI agents</div>
        </div>
        <div className="card kpi">
          <div className="label">Unused permissions (60d)</div>
          <div className="value">{d.unused_pct}%</div>
          <div className="sub">{d.unused_permissions} of {d.effective_permissions} effective · <Link to="/least-privilege">{d.recommendations.remove} safe revokes</Link></div>
        </div>
        <div className="card kpi alert">
          <div className="label">Policy violations</div>
          <div className="value">{d.violations.total}</div>
          <div className="sub">{sev.critical ?? 0} critical · {sev.high ?? 0} high · {sev.medium ?? 0} medium</div>
        </div>
        <div className="card kpi">
          <div className="label">Non-human risk</div>
          <div className="value">{d.nhi.orphaned}</div>
          <div className="sub">orphaned NHIs · {d.nhi.stale_secrets} stale secrets · {d.nhi.agents_with_pii} agents with PII</div>
        </div>
      </div>
      <div className="grid g4 mt">
        <Link to="/jit" className="card kpi"><div className="label">JIT requests pending</div><div className="value">{d.jit.pending}</div><div className="sub">{d.jit.active} active elevation(s)</div></Link>
        <Link to="/reviews" className="card kpi"><div className="label">Review items open</div><div className="value">{d.reviews.open_items}</div><div className="sub">exception-only campaigns</div></Link>
        <Link to="/lifecycle" className="card kpi"><div className="label">HRIS events pending</div><div className="value">{d.hris_pending}</div><div className="sub">joiner / mover / leaver</div></Link>
        <div className="card kpi"><div className="label">Graph</div><div className="value">{d.accounts}</div><div className="sub">accounts across {d.systems} systems · {d.grants} grants</div></div>
      </div>
      <div className="grid g21 mt">
        <div className="card flush">
          <div className="card-h"><h2>Riskiest identities</h2><Link to="/identities" className="small">All identities →</Link></div>
          <table>
            <thead><tr><th>Identity</th><th>Type</th><th className="num">Effective</th><th className="num">Unused</th><th className="num">Privileged</th><th className="num">Violations</th><th>Risk</th></tr></thead>
            <tbody>
              {d.top_risky.map((i: any) => (
                <tr key={i.id} className="click" onClick={() => nav(`/identities/${i.id}`)}>
                  <td><b>{i.name}</b><div className="small muted">{i.title ?? i.department}</div></td>
                  <td><TypeBadge type={i.type} /></td>
                  <td className="num">{i.effective}</td>
                  <td className="num">{i.unused}</td>
                  <td className="num">{i.privileged}</td>
                  <td className="num">{i.violations}</td>
                  <td style={{ width: 120 }}><Bar value={i.risk} risk /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h2>Violations by policy</h2>
          {policies.map(([name, n]) => (
            <div key={name} style={{ marginBottom: 10 }}>
              <div className="spread small"><Link to="/policies">{name}</Link><b>{n}</b></div>
              <Bar value={n} max={maxPol} />
            </div>
          ))}
        </div>
      </div>
      <div className="card mt">
        <div className="spread"><h2>Permission usage, last 90 days</h2><span className="small muted">daily events ingested from connector audit logs</span></div>
        <Trend points={d.usage_trend} />
      </div>
    </Page>
  );
}
