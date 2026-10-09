import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useApi } from "../api";
import { Bar, Loading, Page, TypeBadge } from "../components/ui";

export default function Identities() {
  const [type, setType] = useState("");
  const [q, setQ] = useState("");
  const { data, error } = useApi<any[]>(`/identities${type ? `?type=${type}` : ""}`);
  const nav = useNavigate();
  const rows = useMemo(
    () => (data ?? []).filter((i) => !q || `${i.name} ${i.email ?? ""} ${i.department ?? ""} ${i.title ?? ""}`.toLowerCase().includes(q.toLowerCase())),
    [data, q],
  );
  return (
    <Page
      title="Identities"
      sub="Every identity correlated across systems, ranked by risk (violations, privilege, sensitive data, unused access)."
      actions={
        <>
          <input placeholder="Search name, team, title…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 240 }} />
          <div className="seg">
            {[["", "All"], ["human", "Humans"], ["service", "Service"], ["ai_agent", "AI agents"]].map(([v, l]) => (
              <button key={v} className={type === v ? "on" : ""} onClick={() => setType(v)}>{l}</button>
            ))}
          </div>
        </>
      }
    >
      {!data ? (
        <Loading error={error} />
      ) : (
        <div className="card flush">
          <table>
            <thead>
              <tr><th>Identity</th><th>Type</th><th>Department / kind</th><th>Systems</th><th className="num">Effective</th><th className="num">Unused 60d</th><th className="num">Privileged</th><th className="num">Violations</th><th>Risk</th></tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.id} className="click" onClick={() => nav(`/identities/${i.id}`)}>
                  <td>
                    <b>{i.name}</b> {i.status !== "active" && <span className="badge bad">{i.status}</span>}
                    <div className="small muted">{i.email ?? ""}</div>
                  </td>
                  <td><TypeBadge type={i.type} /></td>
                  <td className="small">{i.department ?? ""}<div className="muted">{i.title}</div></td>
                  <td><div className="row" style={{ gap: 4 }}>{i.systems.map((s: string) => <span key={s} className="chip sys">{s}</span>)}</div></td>
                  <td className="num">{i.effective ?? 0}</td>
                  <td className="num">{i.unused ?? 0}</td>
                  <td className="num">{i.privileged ?? 0}</td>
                  <td className="num">{i.violations ? <span className="badge bad">{i.violations}</span> : 0}</td>
                  <td style={{ width: 110 }}><Bar value={i.risk ?? 0} risk /></td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="empty">No identities match.</div>}
        </div>
      )}
    </Page>
  );
}
