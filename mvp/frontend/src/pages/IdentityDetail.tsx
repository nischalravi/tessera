import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { SimResult, ago, api, fmtDay, useApi } from "../api";
import { Drawer, IdLink, Loading, Page, PathView, Sev, SimulationView, TypeBadge } from "../components/ui";

export function RevokeDrawer({ edgeId, onClose, onDone }: { edgeId: number; onClose: () => void; onDone?: () => void }) {
  const [res, setRes] = useState<SimResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    api<SimResult>("/least-privilege/revoke", { edge_id: edgeId, dry_run: true })
      .then((r) => alive && setRes(r))
      .catch((e) => alive && setErr(e.message));
    return () => {
      alive = false;
    };
  }, [edgeId]);
  const apply = async () => {
    setBusy(true);
    try {
      const r = await api<SimResult>("/least-privilege/revoke", { edge_id: edgeId, dry_run: false });
      setRes(r);
      onDone?.();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer
      title={res?.applied ? "Grant revoked" : "Revoke — dry run"}
      sub={res?.grant?.label}
      onClose={onClose}
      footer={
        res && !res.applied ? (
          <>
            <button onClick={onClose}>Cancel</button>
            <button className="danger solid" disabled={busy} onClick={apply}>Revoke grant</button>
          </>
        ) : (
          <button onClick={onClose}>Close</button>
        )
      }
    >
      {err && <div className="err">{err}</div>}
      {res?.applied && <div className="callout ok" style={{ marginBottom: 12 }}>Applied. The grant was removed and an audit record written.</div>}
      {res ? <SimulationView r={res} /> : !err && <div className="empty">Computing blast radius…</div>}
    </Drawer>
  );
}

export default function IdentityDetail() {
  const { id } = useParams();
  const { data: d, error, reload } = useApi<any>(`/identities/${id}`);
  const [tab, setTab] = useState("perms");
  const [open, setOpen] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [revoke, setRevoke] = useState<number | null>(null);
  if (!d) return <Loading error={error} />;
  const perms = (d.effective_permissions as any[]).filter((p) => !filter || (filter === "unused" ? p.unused : filter === "privileged" ? p.privileged : p.tags.length));
  const tabs: [string, string][] = [
    ["perms", `Effective permissions (${d.effective_permissions.length})`],
    ["grants", `Grants (${d.grants.length})`],
    ["violations", `Violations (${d.violations.length})`],
    ["recs", `Recommendations (${d.recommendations.length})`],
    ["accounts", `Accounts & secrets (${d.accounts.length})`],
  ];
  if (d.delegations.length || d.owned_identities.length) tabs.push(["delegation", "Delegation & ownership"]);
  return (
    <Page
      title={d.name}
      sub={
        <span className="row">
          <TypeBadge type={d.type} />
          {d.status !== "active" && <span className="badge bad">{d.status}</span>}
          <span>{[d.title, d.department].filter(Boolean).join(" · ")}</span>
          {d.manager && <span className="muted">Manager: <IdLink i={d.manager} /></span>}
          {d.owner && <span className="muted">Owner: <IdLink i={d.owner} /></span>}
          {d.type !== "human" && !d.owner && <span className="badge bad">No owner</span>}
        </span>
      }
      actions={<Link to={`/graph?identity=${d.id}`}><button>Open in graph</button></Link>}
    >
      {d.description && <div className="callout" style={{ marginBottom: 14 }}>{d.description}</div>}
      <div className="card" style={{ marginBottom: 14 }}>
        <div className="stat-row">
          <div className="s"><b>{d.risk?.effective ?? 0}</b><span>effective permissions</span></div>
          <div className="s"><b>{d.risk?.unused ?? 0}</b><span>unused 60d</span></div>
          <div className="s"><b>{d.risk?.privileged ?? 0}</b><span>privileged</span></div>
          <div className="s"><b>{d.risk?.sensitive ?? 0}</b><span>on sensitive data</span></div>
          <div className="s"><b style={{ color: d.violations.length ? "var(--crit)" : undefined }}>{d.violations.length}</b><span>violations</span></div>
          <div className="s"><b>{d.accounts.length}</b><span>accounts</span></div>
        </div>
      </div>
      <div className="tabs">
        {tabs.map(([k, l]) => <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}
      </div>

      {tab === "perms" && (
        <div className="card flush">
          <div className="card-h">
            <span className="small muted">Click a permission to see every path that grants it.</span>
            <div className="seg">
              {[["", "All"], ["unused", "Unused"], ["privileged", "Privileged"], ["sensitive", "Sensitive"]].map(([v, l]) => (
                <button key={v} className={filter === v ? "on" : ""} onClick={() => setFilter(v)}>{l}</button>
              ))}
            </div>
          </div>
          <table>
            <thead><tr><th>Permission</th><th>Resource</th><th>System</th><th>Last used</th><th className="num">Events 90d</th><th>Paths</th></tr></thead>
            <tbody>
              {perms.map((p) => [
                <tr key={p.perm_key} className="click" onClick={() => setOpen(open === p.perm_key ? null : p.perm_key)}>
                  <td>
                    <b>{p.action}</b> {p.privileged && <span className="badge warn">privileged</span>} {!p.standing && <span className="badge info">JIT</span>}
                  </td>
                  <td>{p.resource} {p.environment && <span className="chip">{p.environment}</span>} {p.tags.map((t: string) => <span key={t} className="chip">{t}</span>)}</td>
                  <td className="sys">{p.system}</td>
                  <td className="nowrap">{p.unused ? <span className="badge warn">{ago(p.usage.days_since_used)}</span> : ago(p.usage.days_since_used)}</td>
                  <td className="num">{p.usage.events_90d}</td>
                  <td className="small muted">{p.paths.length} {open === p.perm_key ? "▾" : "▸"}</td>
                </tr>,
                open === p.perm_key && (
                  <tr key={p.perm_key + "-x"}>
                    <td colSpan={6} style={{ background: "#fafbff" }}>
                      {p.paths.map((path: any, i: number) => <div key={i} style={{ marginBottom: 6 }}><PathView steps={path} /></div>)}
                      <Link className="small" to={`/graph?identity=${d.id}&perm=${encodeURIComponent(p.perm_key)}`}>Show in graph →</Link>
                    </td>
                  </tr>
                ),
              ])}
            </tbody>
          </table>
          {perms.length === 0 && <div className="empty">Nothing here.</div>}
        </div>
      )}

      {tab === "grants" && (
        <div className="card flush">
          <table>
            <thead><tr><th>Account</th><th>Granted</th><th>Type</th><th>Expires</th><th></th></tr></thead>
            <tbody>
              {d.grants.map((g: any) => (
                <tr key={g.src + g.dst}>
                  <td className="sys">{g.account}</td>
                  <td><b>{g.label}</b> {g.privileged && <span className="badge warn">privileged</span>}</td>
                  <td>{g.source === "jit" ? <span className="badge info">JIT</span> : <span className="muted small">{g.relation}</span>}</td>
                  <td className="small">{g.expires_at ? new Date(g.expires_at + "Z").toLocaleString() : "standing"}</td>
                  <td className="num">{g.edge_id && <button className="sm danger" onClick={() => setRevoke(g.edge_id)}>Revoke…</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "violations" && (
        <div className="stack">
          {d.violations.length === 0 && <div className="card empty">No policy violations.</div>}
          {d.violations.map((v: any) => (
            <div key={v.key} className="card">
              <div className="row"><Sev s={v.severity} /><b>{v.policy_name}</b></div>
              <div style={{ margin: "6px 0" }}>{v.message}</div>
              {v.evidence.map((e: string, i: number) => <div key={i} className="small muted">• {e}</div>)}
            </div>
          ))}
        </div>
      )}

      {tab === "recs" && (
        <div className="card flush">
          <table>
            <thead><tr><th>Grant</th><th>Recommendation</th><th className="num">Unused / lost</th><th>Last used</th><th></th></tr></thead>
            <tbody>
              {d.recommendations.map((r: any) => (
                <tr key={r.edge_id}>
                  <td><b>{r.target}</b><div className="small muted">{r.unused_examples.slice(0, 3).join(", ")}</div></td>
                  <td><span className={`badge ${r.kind === "remove" ? "bad" : r.kind === "right_size" ? "warn" : ""}`}>{r.kind.replace("_", " ")}</span><div className="small muted">{r.rationale}</div></td>
                  <td className="num">{r.unused_lost} / {r.permissions_lost}</td>
                  <td className="small">{ago(r.days_since_used)}</td>
                  <td><button className="sm" onClick={() => setRevoke(r.edge_id)}>Dry-run revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          {d.recommendations.length === 0 && <div className="empty">No recommendations — access matches usage.</div>}
        </div>
      )}

      {tab === "accounts" && (
        <div className="grid g2">
          <div className="card flush">
            <div className="card-h"><h2>Accounts</h2></div>
            <table>
              <thead><tr><th>System</th><th>Username</th><th>Kind</th><th>Status</th><th>Last login</th></tr></thead>
              <tbody>
                {d.accounts.map((a: any) => (
                  <tr key={a.id}>
                    <td className="sys">{a.system}</td><td>{a.username}</td><td className="small">{a.kind}</td>
                    <td>{a.status === "active" ? <span className="badge ok">active</span> : <span className="badge">{a.status}</span>}</td>
                    <td className="small">{fmtDay(a.last_login_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="card flush">
            <div className="card-h"><h2>Secrets & credentials</h2></div>
            <table>
              <thead><tr><th>Secret</th><th>Kind</th><th className="num">Age</th><th>Last used</th></tr></thead>
              <tbody>
                {d.secrets.map((s: any) => (
                  <tr key={s.id}>
                    <td className="sys">{s.name}</td><td className="small">{s.kind}</td>
                    <td className="num">{s.stale ? <span className="badge warn">{s.age_days}d</span> : `${s.age_days}d`}</td>
                    <td className="small">{ago(s.last_used_days)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {d.secrets.length === 0 && <div className="empty">No machine credentials.</div>}
          </div>
        </div>
      )}

      {tab === "delegation" && (
        <div className="grid g2">
          <div className="card">
            <h2>Delegations</h2>
            {d.delegations.length === 0 && <div className="muted">None</div>}
            {d.delegations.map((x: any, i: number) => (
              <div key={i} style={{ marginBottom: 10 }}>
                <IdLink i={x.agent} /> acts on behalf of <IdLink i={x.principal} />
                <div className="row" style={{ marginTop: 4 }}>{x.scopes.map((s: string) => <span key={s} className="chip sys">{s}</span>)}</div>
              </div>
            ))}
          </div>
          <div className="card">
            <h2>Owns</h2>
            {d.owned_identities.length === 0 && <div className="muted">Nothing</div>}
            {d.owned_identities.map((o: any) => (
              <div key={o.id} className="row" style={{ marginBottom: 6 }}><TypeBadge type={o.type} /><IdLink i={o} /><span className="small muted">{o.title}</span></div>
            ))}
          </div>
        </div>
      )}
      {revoke !== null && <RevokeDrawer edgeId={revoke} onClose={() => setRevoke(null)} onDone={reload} />}
    </Page>
  );
}
