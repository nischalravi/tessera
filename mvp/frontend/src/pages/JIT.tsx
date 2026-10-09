import { useEffect, useState } from "react";
import { api, fmtDate, useApi } from "../api";
import { IdLink, Loading, Page, TypeBadge } from "../components/ui";

function Countdown({ until }: { until: string }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const ms = new Date(until + "Z").getTime() - now;
  if (ms <= 0) return <span className="badge">expiring…</span>;
  const h = Math.floor(ms / 3.6e6), m = Math.floor((ms % 3.6e6) / 6e4), s = Math.floor((ms % 6e4) / 1000);
  return <span className="badge info">{h}h {String(m).padStart(2, "0")}m {String(s).padStart(2, "0")}s left</span>;
}

const STATUS: Record<string, string> = { pending: "medium", approved: "ok", denied: "bad", expired: "", revoked: "" };

export default function JIT() {
  const { data, error, reload } = useApi<any[]>("/jit/requests");
  const { data: groups } = useApi<any[]>("/groups?requestable=true");
  const { data: idents } = useApi<any[]>("/identities?status=active");
  const [form, setForm] = useState({ identity_id: "", group_id: "", duration_hours: 2, justification: "" });
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    const t = setInterval(reload, 15000);
    return () => clearInterval(t);
  }, [reload]);
  const submit = async () => {
    setMsg(null);
    try {
      await api("/jit/requests", { ...form, identity_id: Number(form.identity_id), group_id: Number(form.group_id), duration_hours: Number(form.duration_hours) });
      setForm({ ...form, justification: "" });
      reload();
    } catch (e: any) {
      setMsg(e.message);
    }
  };
  const act = async (id: number, a: string) => {
    try {
      await api(`/jit/requests/${id}/${a}`, { approver: "security-oncall@larkspur.example" });
      reload();
    } catch (e: any) {
      setMsg(e.message);
    }
  };
  return (
    <Page title="Just-in-time access" sub="Privileged roles are requested for a bounded time, approved, and removed automatically on expiry (the sweeper runs every 30 seconds). JIT grants never count as standing access.">
      <div className="grid g21">
        <div className="card flush">
          <div className="card-h"><h2>Requests</h2><button className="sm" onClick={reload}>Refresh</button></div>
          {!data ? <Loading error={error} /> : (
            <table>
              <thead><tr><th>Requester</th><th>Role</th><th>Justification</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {data.map((r) => (
                  <tr key={r.id}>
                    <td><IdLink i={r.identity} /><div className="row" style={{ marginTop: 3 }}><TypeBadge type={r.identity.type} /></div></td>
                    <td><b>{r.group.name}</b> <span className="chip sys">{r.group.system}</span><div className="small muted">{r.duration_hours}h via {r.account}</div></td>
                    <td className="small" style={{ maxWidth: 280 }}>{r.justification}<div className="faint">requested {fmtDate(r.requested_at)}</div></td>
                    <td className="small">
                      <span className={`badge ${STATUS[r.status]}`}>{r.status}</span>
                      {r.status === "approved" && r.expires_at && <div style={{ marginTop: 4 }}><Countdown until={r.expires_at} /></div>}
                      {r.decided_by && <div className="faint">by {r.decided_by}</div>}
                    </td>
                    <td className="nowrap">
                      {r.status === "pending" && (
                        <div className="row">
                          <button className="sm primary" onClick={() => act(r.id, "approve")}>Approve</button>
                          <button className="sm" onClick={() => act(r.id, "deny")}>Deny</button>
                        </div>
                      )}
                      {r.status === "approved" && <button className="sm danger" onClick={() => act(r.id, "revoke")}>Revoke now</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <div className="card stack">
          <h2>Request access</h2>
          <label className="f">Identity
            <select value={form.identity_id} onChange={(e) => setForm({ ...form, identity_id: e.target.value })}>
              <option value="">Select…</option>
              {(idents ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)).map((i) => <option key={i.id} value={i.id}>{i.name} ({i.type})</option>)}
            </select>
          </label>
          <label className="f">Eligible role
            <select value={form.group_id} onChange={(e) => setForm({ ...form, group_id: e.target.value })}>
              <option value="">Select…</option>
              {(groups ?? []).map((g) => <option key={g.id} value={g.id}>{g.system}: {g.name}</option>)}
            </select>
          </label>
          <label className="f">Duration (hours, max 72)
            <input type="number" min={0.05} max={72} step={0.25} value={form.duration_hours} onChange={(e) => setForm({ ...form, duration_hours: Number(e.target.value) })} />
          </label>
          <label className="f">Justification
            <textarea value={form.justification} onChange={(e) => setForm({ ...form, justification: e.target.value })} placeholder="Incident / ticket reference" />
          </label>
          {msg && <div className="err">{msg}</div>}
          <button className="primary" disabled={!form.identity_id || !form.group_id || !form.justification} onClick={submit}>Submit request</button>
          <div className="small muted">Tip: request 0.05h (3 minutes), approve it, and watch it expire automatically.</div>
        </div>
      </div>
    </Page>
  );
}
