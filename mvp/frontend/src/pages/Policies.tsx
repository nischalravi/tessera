import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { SimResult, Violation, api, useApi } from "../api";
import { Loading, Page, Sev, SimulationView } from "../components/ui";

function Simulator() {
  const { data: idents } = useApi<any[]>("/identities?status=active");
  const { data: groups } = useApi<any[]>("/groups");
  const [iid, setIid] = useState("");
  const { data: ident } = useApi<any>(iid ? `/identities/${iid}` : null);
  const [remove, setRemove] = useState<number[]>([]);
  const [addAcct, setAddAcct] = useState("");
  const [addGroup, setAddGroup] = useState("");
  const [res, setRes] = useState<SimResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const run = async () => {
    setErr(null);
    try {
      setRes(await api<SimResult>("/simulate", {
        remove_edge_ids: remove,
        add_edges: addAcct && addGroup ? [{ src: `account:${addAcct}`, dst: `group:${addGroup}` }] : [],
      }));
    } catch (e: any) {
      setErr(e.message);
    }
  };
  return (
    <div className="card stack">
      <h2>What-if simulation</h2>
      <div className="small muted">Pick an identity, then remove existing grants and/or add a membership. Nothing is changed — Tessera recomputes effective permissions and every policy on a copy of the graph.</div>
      <label className="f">Identity
        <select value={iid} onChange={(e) => { setIid(e.target.value); setRemove([]); setAddAcct(""); setRes(null); }}>
          <option value="">Select…</option>
          {(idents ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)).map((i) => <option key={i.id} value={i.id}>{i.name} ({i.type})</option>)}
        </select>
      </label>
      {ident && (
        <>
          <div>
            <div className="small muted" style={{ marginBottom: 4 }}>Remove grants</div>
            {ident.grants.filter((g: any) => g.edge_id).map((g: any) => (
              <label key={g.edge_id} className="row small" style={{ marginBottom: 3 }}>
                <input type="checkbox" checked={remove.includes(g.edge_id)} onChange={(e) => setRemove(e.target.checked ? [...remove, g.edge_id] : remove.filter((x) => x !== g.edge_id))} />
                <span className="sys">{g.account}</span> → <b>{g.label}</b>
              </label>
            ))}
          </div>
          <div className="row">
            <label className="f" style={{ flex: 1 }}>Add: account
              <select value={addAcct} onChange={(e) => setAddAcct(e.target.value)}>
                <option value="">—</option>
                {ident.accounts.filter((a: any) => a.status === "active").map((a: any) => <option key={a.id} value={a.id}>{a.system}: {a.username}</option>)}
              </select>
            </label>
            <label className="f" style={{ flex: 1 }}>to group / role
              <select value={addGroup} onChange={(e) => setAddGroup(e.target.value)}>
                <option value="">—</option>
                {(groups ?? []).map((g) => <option key={g.id} value={g.id}>{g.system}: {g.name}</option>)}
              </select>
            </label>
          </div>
        </>
      )}
      {err && <div className="err">{err}</div>}
      <button className="primary" disabled={!iid || (!remove.length && !(addAcct && addGroup))} onClick={run}>Run simulation</button>
      {res && <SimulationView r={res} />}
    </div>
  );
}

export default function Policies() {
  const { data: policies, error } = useApi<any[]>("/policies");
  const { data: violations } = useApi<Violation[]>("/violations");
  const [pid, setPid] = useState("");
  const [yaml, setYaml] = useState<string | null>(null);
  const rows = useMemo(() => (violations ?? []).filter((v) => !pid || v.policy_id === pid), [violations, pid]);
  if (!policies) return <Loading error={error} />;
  return (
    <Page title="Policies & violations" sub={<>Policies are YAML files in <code>server/policies/</code>, evaluated against the effective-permission graph. Edit a file and reload — no restart needed.</>}>
      <div className="grid g3">
        {policies.map((p) => (
          <div key={p.id} className="card" style={{ cursor: "pointer", outline: pid === p.id ? "2px solid var(--brand)" : undefined }} onClick={() => setPid(pid === p.id ? "" : p.id)}>
            <div className="spread"><Sev s={p.severity} /><span className={`badge ${p.violations ? "bad" : "ok"}`}>{p.violations} violation{p.violations === 1 ? "" : "s"}</span></div>
            <div style={{ fontWeight: 600, margin: "8px 0 4px" }}>{p.name}</div>
            <div className="small muted">{p.description}</div>
            <div className="spread" style={{ marginTop: 8 }}>
              <code className="faint">{p.type}</code>
              <button className="ghost sm" onClick={(e) => { e.stopPropagation(); setYaml(yaml === p.id ? null : p.id); }}>{yaml === p.id ? "Hide" : "View"} YAML</button>
            </div>
            {yaml === p.id && <pre className="yaml">{p.source}</pre>}
          </div>
        ))}
      </div>
      <div className="grid g21 mt">
        <div className="card flush">
          <div className="card-h"><h2>Violations {pid && <span className="muted">— {policies.find((p) => p.id === pid)?.name}</span>}</h2><span className="small muted">{rows.length}</span></div>
          <table>
            <thead><tr><th>Severity</th><th>Identity</th><th>Finding</th></tr></thead>
            <tbody>
              {rows.map((v) => (
                <tr key={v.key}>
                  <td><Sev s={v.severity} /></td>
                  <td className="nowrap">{v.identity_id ? <Link to={`/identities/${v.identity_id}`}>{v.identity_name}</Link> : v.identity_name}</td>
                  <td className="small">
                    {v.message}
                    {v.evidence.slice(0, 2).map((e, i) => <div key={i} className="faint">{e}</div>)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Simulator />
      </div>
    </Page>
  );
}
