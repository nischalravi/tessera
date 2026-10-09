import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, useApi } from "../api";
import { Loading, Page, TypeBadge } from "../components/ui";
import { RevokeDrawer } from "./IdentityDetail";

export default function LeastPrivilege() {
  const [days, setDays] = useState(60);
  const [kind, setKind] = useState("remove");
  const [itype, setItype] = useState("");
  const { data, error, reload } = useApi<any[]>(`/least-privilege/recommendations?unused_days=${days}${kind ? `&kind=${kind}` : ""}${itype ? `&identity_type=${itype}` : ""}`);
  const [revoke, setRevoke] = useState<number | null>(null);
  const totalUnused = (data ?? []).reduce((a, r) => a + r.unused_lost, 0);
  return (
    <Page
      title="Least-privilege recommendations"
      sub="Grants whose permissions have gone unused, computed from per-identity usage events. Every revoke shows its blast radius before anything changes."
      actions={
        <>
          <label className="row small muted">Unused for
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
              {[30, 60, 90].map((d) => <option key={d} value={d}>{d} days</option>)}
            </select>
          </label>
          <div className="seg">
            {[["remove", "Safe to remove"], ["role_trim", "Role trims"], ["right_size", "Right-size"], ["", "All"]].map(([v, l]) => (
              <button key={v} className={kind === v ? "on" : ""} onClick={() => setKind(v)}>{l}</button>
            ))}
          </div>
          <div className="seg">
            {[["", "Everyone"], ["human", "Humans"], ["service", "Service"], ["ai_agent", "Agents"]].map(([v, l]) => (
              <button key={v} className={itype === v ? "on" : ""} onClick={() => setItype(v)}>{l}</button>
            ))}
          </div>
        </>
      }
    >
      {!data ? (
        <Loading error={error} />
      ) : (
        <>
          <div className="callout" style={{ marginBottom: 14 }}>
            {data.length} recommendation(s) would remove <b>{totalUnused}</b> unused permission(s). <i>Safe to remove</i> = nothing the grant uniquely provides was used in {days} days; <i>role trim</i> = a permission inside a role that none of its holders used; <i>right-size</i> = most of a grant was unused.
          </div>
          <div className="card flush">
            <table>
              <thead><tr><th>Identity / holders</th><th>Grant</th><th>Why</th><th className="num">Unused / lost</th><th>Last used</th><th></th></tr></thead>
              <tbody>
                {data.map((r) => (
                  <tr key={r.edge_id}>
                    {r.kind === "role_trim" ? (
                      <td style={{ maxWidth: 220 }}>
                        <b>{r.identity_name}</b>
                        <div className="small muted">{r.holders.slice(0, 4).join(", ")}{r.holders.length > 4 ? " …" : ""}</div>
                      </td>
                    ) : (
                      <td>
                        <Link to={`/identities/${r.identity_id}`}><b>{r.identity_name}</b></Link>
                        <div className="row" style={{ marginTop: 3 }}><TypeBadge type={r.identity_type} /><span className="small muted">{r.department}</span></div>
                      </td>
                    )}
                    <td>
                      <b>{r.target}</b> {r.target_privileged && <span className="badge warn">privileged</span>}
                      <div className="small muted sys">{r.grant}</div>
                      <div className="row" style={{ marginTop: 3, gap: 4 }}>{r.sensitive_tags.map((t: string) => <span key={t} className="chip">{t}</span>)}</div>
                    </td>
                    <td className="small" style={{ maxWidth: 340 }}>
                      <span className={`badge ${r.kind === "remove" ? "bad" : r.kind === "role_trim" ? "info" : "warn"}`}>{r.kind.replace("_", " ")}</span> {r.rationale}
                      <div className="muted" style={{ marginTop: 3 }}>Unused: {r.unused_examples.slice(0, 3).join("; ")}</div>
                      {r.used_examples.length > 0 && <div className="muted">Still used: {r.used_examples.slice(0, 2).join("; ")}</div>}
                    </td>
                    <td className="num">{r.unused_lost} / {r.permissions_lost}{r.privileged_unused > 0 && <div className="small faint">{r.privileged_unused} privileged</div>}</td>
                    <td className="small nowrap">{ago(r.days_since_used)}</td>
                    <td><button className="sm" onClick={() => setRevoke(r.edge_id)}>Dry-run revoke</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data.length === 0 && <div className="empty">No recommendations for this filter.</div>}
          </div>
        </>
      )}
      {revoke !== null && <RevokeDrawer edgeId={revoke} onClose={() => setRevoke(null)} onDone={reload} />}
    </Page>
  );
}
