import { useEffect, useState } from "react";
import { api, ago, fmtDate, useApi } from "../api";
import { Flag, IdLink, Loading, Page, TypeBadge } from "../components/ui";

function Campaign({ id, onChange }: { id: number; onChange: () => void }) {
  const { data, error, reload } = useApi<any>(`/reviews/campaigns/${id}`);
  const [reason, setReason] = useState("");
  const [showDone, setShowDone] = useState(false);
  if (!data) return <Loading error={error} />;
  const decide = async (itemId: number, decision: string) => {
    await api(`/reviews/items/${itemId}/decision`, { decision, reviewer: "reviewer@larkspur.example" });
    reload();
    onChange();
  };
  const items = (data.review_items as any[]).filter((i) => (!reason || i.reasons.includes(reason)) && (showDone || !i.decision));
  const pctAuto = data.total_grants ? Math.round((100 * data.auto_certified) / data.total_grants) : 0;
  return (
    <div className="stack">
      <div className="card">
        <div className="stat-row">
          <div className="s"><b>{data.total_grants}</b><span>grants in scope</span></div>
          <div className="s"><b style={{ color: "var(--ok)" }}>{data.auto_certified}</b><span>auto-certified ({pctAuto}%)</span></div>
          <div className="s"><b>{data.items}</b><span>need a human</span></div>
          <div className="s"><b>{data.decided}</b><span>decided</span></div>
          <div className="s"><b>{data.revoked}</b><span>revoked</span></div>
        </div>
        <div className="small muted mt">Only exceptions are routed to reviewers: grants unused for {data.unused_days}+ days, implicated in a policy violation, held by leavers or orphaned NHIs, or privileged and idle. Everything else was auto-certified based on usage evidence.</div>
      </div>
      <div className="row">
        <div className="seg">
          <button className={!reason ? "on" : ""} onClick={() => setReason("")}>All reasons</button>
          {Object.entries(data.reasons as Record<string, number>).map(([r, n]) => (
            <button key={r} className={reason === r ? "on" : ""} onClick={() => setReason(r)}>{r.replace(/_/g, " ")} ({n})</button>
          ))}
        </div>
        <label className="row small muted"><input type="checkbox" checked={showDone} onChange={(e) => setShowDone(e.target.checked)} /> show decided</label>
      </div>
      <div className="card flush">
        <table>
          <thead><tr><th>Identity</th><th>Access</th><th>Why it's here</th><th>Usage context</th><th>Reviewer</th><th>Decision</th></tr></thead>
          <tbody>
            {items.map((it) => (
              <tr key={it.id}>
                <td><IdLink i={it.identity} /><div style={{ marginTop: 3 }}><TypeBadge type={it.identity.type} /></div></td>
                <td style={{ maxWidth: 260 }}>
                  <b className="small">{it.grant.split(" → ")[1]}</b>
                  <div className="small muted sys">{it.grant.split(" → ")[0]}</div>
                  <div className="small faint">{it.context.sample_permissions.slice(0, 2).join("; ")}</div>
                </td>
                <td><div className="row" style={{ gap: 4 }}>{it.reasons.map((r: string) => <Flag key={r} f={r} />)}</div>
                  {it.context.violations.length > 0 && <div className="small muted" style={{ marginTop: 4 }}>{it.context.violations.join("; ")}</div>}
                </td>
                <td className="small">
                  {it.context.permissions_used}/{it.context.permissions} perms used · last {ago(it.context.days_since_used)}
                  <div className="muted">{it.context.events_90d} events in 90d</div>
                  {it.context.peer_coverage !== null && <div className="muted">{Math.round(it.context.peer_coverage * 100)}% of dept peers hold this</div>}
                </td>
                <td className="small"><IdLink i={it.reviewer} /></td>
                <td className="nowrap">
                  {it.decision ? (
                    <span className={`badge ${it.decision === "revoke" ? "bad" : "ok"}`}>{it.decision}</span>
                  ) : (
                    <div className="row">
                      <button className="sm" onClick={() => decide(it.id, "keep")}>Keep</button>
                      <button className="sm danger" onClick={() => decide(it.id, "revoke")}>Revoke</button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {items.length === 0 && <div className="empty">Nothing left to review here.</div>}
      </div>
    </div>
  );
}

export default function Reviews() {
  const { data, error, reload } = useApi<any[]>("/reviews/campaigns");
  const [sel, setSel] = useState<number | null>(null);
  const [days, setDays] = useState(60);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (data && data.length && sel === null) setSel(data[0].id);
  }, [data, sel]);
  const create = async () => {
    setBusy(true);
    const c = await api<any>("/reviews/campaigns", { name: `Exception review (${days}d) — ${new Date().toLocaleDateString()}`, unused_days: days });
    setBusy(false);
    reload();
    setSel(c.id);
  };
  if (!data) return <Loading error={error} />;
  return (
    <Page
      title="Access reviews"
      sub="Exception-only certification: reviewers see only risky or unused access, with usage and peer context for each decision. Revoke decisions are applied to the graph immediately."
      actions={
        <>
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {[30, 60, 90].map((d) => <option key={d} value={d}>unused ≥ {d}d</option>)}
          </select>
          <button className="primary" disabled={busy} onClick={create}>Generate campaign</button>
        </>
      }
    >
      <div className="row" style={{ marginBottom: 14 }}>
        {data.map((c) => (
          <button key={c.id} className={sel === c.id ? "primary" : ""} onClick={() => setSel(c.id)}>
            {c.name} <span style={{ opacity: 0.7 }}>· {c.decided}/{c.items}</span>
          </button>
        ))}
      </div>
      {sel !== null && <Campaign key={sel} id={sel} onChange={reload} />}
      {data.length === 0 && <div className="card empty">No campaigns yet.</div>}
      <div className="small faint mt">{data[0] && `Latest campaign created ${fmtDate(data[0].created_at)}`}</div>
    </Page>
  );
}
