import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ago, useApi } from "../api";
import { Bar, Flag, Loading, Page } from "../components/ui";

function Agent({ a }: { a: any }) {
  return (
    <div className="card">
      <div className="spread">
        <div>
          <Link to={`/identities/${a.id}`}><b style={{ fontSize: 15 }}>{a.name}</b></Link>
          <div className="small muted">{a.description}</div>
        </div>
        <div style={{ width: 90 }}><Bar value={a.risk} risk /></div>
      </div>
      <div className="row mt">{a.flags.map((f: string) => <Flag key={f} f={f} />)}</div>
      <h3 className="mt">Delegation chain</h3>
      {a.delegations.length === 0 && <div className="muted small">No delegations</div>}
      {a.delegations.map((d: any, i: number) => (
        <div key={i} style={{ marginBottom: 10 }}>
          <div className="chain">
            {d.chain.map((c: any, j: number) => (
              <span key={j} className="row" style={{ gap: 6 }}>
                {j > 0 && <span className="faint">→</span>}
                <span className={`lnk ${c.status !== "active" ? "bad" : ""}`}>
                  <small>{c.role.replace(/_/g, " ")}</small>
                  {c.name}
                  {c.status !== "active" && <span className="badge bad" style={{ marginLeft: 4 }}>left</span>}
                </span>
              </span>
            ))}
          </div>
          <div className="row" style={{ marginTop: 6 }}>
            <span className="small muted">Tool scopes:</span>
            {d.scopes.map((s: string) => <span key={s} className="chip sys">{s}</span>)}
          </div>
          {d.exceeds_principal.length > 0 && (
            <div className="callout warn small" style={{ marginTop: 6 }}>
              Agent holds {d.exceeds_principal.length} permission(s) its principal does not — e.g. {d.exceeds_principal.slice(0, 2).join("; ")}
            </div>
          )}
        </div>
      ))}
      <div className="small muted mt">
        {a.effective_permissions} effective permissions · {a.privileged_permissions} privileged · systems: {a.systems.join(", ")} · last active {ago(a.days_since_activity)}
      </div>
    </div>
  );
}

export default function NHI() {
  const { data, error } = useApi<any[]>("/nhi");
  const [flag, setFlag] = useState("");
  const nav = useNavigate();
  if (!data) return <Loading error={error} />;
  const agents = data.filter((x) => x.type === "ai_agent");
  const svcs = data.filter((x) => x.type === "service" && (!flag || x.flags.includes(flag)));
  const count = (f: string) => data.filter((x) => x.type === "service" && x.flags.includes(f)).length;
  return (
    <Page title="Non-human identities & AI agents" sub="Service accounts, API keys, integration users and AI agents — who owns them, how old their secrets are, and what they can reach.">
      <h2>AI agents ({agents.length})</h2>
      <div className="grid g2">{agents.map((a) => <Agent key={a.id} a={a} />)}</div>
      <div className="spread mt" style={{ marginTop: 26 }}>
        <h2 style={{ margin: 0 }}>Service accounts & API keys ({data.length - agents.length})</h2>
        <div className="seg">
          {[["", "All"], ["orphaned", `No owner (${count("orphaned")})`], ["owner_left", `Owner left (${count("owner_left")})`], ["stale_secret", `Stale secret (${count("stale_secret")})`], ["dormant", `Dormant (${count("dormant")})`]].map(([v, l]) => (
            <button key={v} className={flag === v ? "on" : ""} onClick={() => setFlag(v)}>{l}</button>
          ))}
        </div>
      </div>
      <div className="card flush mt">
        <table>
          <thead><tr><th>Identity</th><th>Owner</th><th>Systems</th><th className="num">Oldest secret</th><th>Last activity</th><th className="num">Perms</th><th>Flags</th><th>Risk</th></tr></thead>
          <tbody>
            {svcs.map((x) => (
              <tr key={x.id} className="click" onClick={() => nav(`/identities/${x.id}`)}>
                <td><b>{x.name}</b><div className="small muted">{x.kind} — {x.description}</div></td>
                <td className="small">{x.owner ? <>{x.owner.name}{x.owner.status !== "active" && <span className="badge bad" style={{ marginLeft: 4 }}>left</span>}</> : <span className="badge bad">none</span>}</td>
                <td>{x.systems.map((s: string) => <span key={s} className="chip sys">{s}</span>)}</td>
                <td className="num">{x.oldest_secret_days == null ? "—" : x.oldest_secret_days > 90 ? <span className="badge warn">{x.oldest_secret_days}d</span> : `${x.oldest_secret_days}d`}</td>
                <td className="small nowrap">{ago(x.days_since_activity)}</td>
                <td className="num">{x.effective_permissions}{x.privileged_permissions > 0 && <span className="faint"> ({x.privileged_permissions} priv)</span>}</td>
                <td><div className="row" style={{ gap: 4 }}>{x.flags.map((f: string) => <Flag key={f} f={f} />)}</div></td>
                <td style={{ width: 90 }}><Bar value={x.risk} risk /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Page>
  );
}
