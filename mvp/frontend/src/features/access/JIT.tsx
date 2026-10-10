import { useEffect, useState } from "react";
import { Timer } from "lucide-react";
import { Group, IdentityRow, JitRequest, fmtDate, jitCreate, jitDecide, useApi } from "../../api";
import { usePersona } from "../../app/persona";
import { Badge, Button, EmptyState, FilterChips, IdLink, Loading, Page, Status, TypeBadge, useConfirm, useToast } from "../../components";

function Countdown({ until }: { until: string }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const ms = new Date(until + "Z").getTime() - now;
  if (ms <= 0) return <Badge>Expiring…</Badge>;
  const h = Math.floor(ms / 3.6e6), m = Math.floor((ms % 3.6e6) / 6e4), s = Math.floor((ms % 6e4) / 1000);
  return <Badge tone="info"><Timer size={11} aria-hidden /> <span className="tnum">{h}h {String(m).padStart(2, "0")}m {String(s).padStart(2, "0")}s</span> left</Badge>;
}

export function JIT() {
  const { data, error, reload } = useApi<JitRequest[]>("/jit/requests");
  const { data: groups } = useApi<Group[]>("/groups?requestable=true");
  const { data: idents } = useApi<IdentityRow[]>("/identities?status=active");
  const { me } = usePersona();
  const toast = useToast();
  const confirm = useConfirm();
  const [form, setForm] = useState({ identity_id: "", group_id: "", duration_hours: 2, justification: "" });
  const [status, setStatus] = useState<"all" | "pending" | "approved" | "closed">("all");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const t = setInterval(reload, 15000);
    return () => clearInterval(t);
  }, [reload]);
  useEffect(() => {
    if (me && !form.identity_id) setForm((f) => ({ ...f, identity_id: String(me.id) }));
  }, [me, form.identity_id]);

  const submit = async () => {
    setBusy(true);
    try {
      await jitCreate({ identity_id: Number(form.identity_id), group_id: Number(form.group_id), duration_hours: Number(form.duration_hours), justification: form.justification });
      setForm({ ...form, justification: "" });
      toast("Request submitted. It's now in the approvers' inbox.");
    } catch (e: any) {
      toast(`Couldn't submit: ${e.message}`, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const act = async (r: JitRequest, a: "approve" | "deny" | "revoke") => {
    if (a === "revoke") {
      const ok = await confirm({ title: `End ${r.identity.name}'s elevation now?`, body: `Removes ${r.group.system}:${r.group.name} immediately instead of waiting for it to expire.`, confirmLabel: "Revoke now", danger: true });
      if (ok === null) return;
    }
    try {
      await jitDecide(r.id, a);
      toast(a === "approve" ? `Approved for ${r.duration_hours} h` : a === "deny" ? "Request denied" : "Elevation revoked");
    } catch (e: any) {
      toast(e.message, { kind: "error" });
    }
  };
  const rows = (data ?? []).filter((r) => status === "all" || (status === "closed" ? !["pending", "approved"].includes(r.status) : r.status === status));
  const count = (s: string) => (data ?? []).filter((r) => (s === "closed" ? !["pending", "approved"].includes(r.status) : r.status === s)).length;

  return (
    <Page title="Just-in-time access" crumbs={[["Access"], ["Just-in-time"]]} sub="Privileged roles are requested for a set time, approved, and removed automatically when they expire. The sweeper runs every 30 seconds. JIT grants never count as standing access.">
      <div className="grid g21">
        <div className="stack">
          <FilterChips label="Status" value={status} onChange={setStatus} options={[{ id: "all", label: "All", count: data?.length }, { id: "pending", label: "Pending", count: count("pending") }, { id: "approved", label: "Active", count: count("approved") }, { id: "closed", label: "Closed", count: count("closed") }]} />
          <div className="card flush">
            {!data ? <Loading error={error} /> : rows.length === 0 ? (
              <EmptyState title="No requests here" icon={<Timer size={18} />}>Request an elevation with the form. It shows here while it's pending and counts down once approved.</EmptyState>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead><tr><th>Requester</th><th>Role</th><th className="hide-narrow">Justification</th><th>Status</th><th /></tr></thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={r.id}>
                        <td><IdLink i={r.identity} /><div style={{ marginTop: 3 }}><TypeBadge type={r.identity.type} /></div></td>
                        <td><b className="sys">{r.group.system}:{r.group.name}</b><div className="xs faint">{r.duration_hours} h via {r.account}</div></td>
                        <td className="small hide-narrow" style={{ maxWidth: 280 }}>{r.justification}<div className="xs faint">requested {fmtDate(r.requested_at)}</div></td>
                        <td className="small">
                          <Status s={r.status === "approved" ? "active" : r.status} />
                          {r.status === "approved" && r.expires_at && <div style={{ marginTop: 4 }}><Countdown until={r.expires_at} /></div>}
                          {r.decided_by && <div className="xs faint">by {r.decided_by}</div>}
                        </td>
                        <td className="actions-cell">
                          {r.status === "pending" && (
                            <div className="row tight" style={{ justifyContent: "flex-end" }}>
                              <Button size="sm" variant="primary" disabled={r.identity.id === me?.id} title={r.identity.id === me?.id ? "You can't approve your own request" : undefined} onClick={() => act(r, "approve")}>Approve</Button>
                              <Button size="sm" onClick={() => act(r, "deny")}>Deny</Button>
                            </div>
                          )}
                          {r.status === "approved" && <Button size="sm" variant="danger" onClick={() => act(r, "revoke")}>Revoke now</Button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
        <form className="card stack" onSubmit={(e) => { e.preventDefault(); submit(); }}>
          <h2>Request an elevation</h2>
          <label className="field">For
            <select className="input" value={form.identity_id} onChange={(e) => setForm({ ...form, identity_id: e.target.value })}>
              <option value="">Select…</option>
              {(idents ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)).map((i) => <option key={i.id} value={i.id}>{i.name}{me?.id === i.id ? " (you)" : ""}</option>)}
            </select>
          </label>
          <label className="field">Eligible role
            <select className="input" value={form.group_id} onChange={(e) => setForm({ ...form, group_id: e.target.value })}>
              <option value="">Select…</option>
              {(groups ?? []).map((g) => <option key={g.id} value={g.id}>{g.system}:{g.name}</option>)}
            </select>
          </label>
          <label className="field">Duration in hours
            <input className="input" type="number" min={0.05} max={72} step={0.25} value={form.duration_hours} onChange={(e) => setForm({ ...form, duration_hours: Number(e.target.value) })} />
            <span className="hint">Up to 72. Try 0.05 (3 minutes), approve it, and watch it expire.</span>
          </label>
          <label className="field">Justification
            <textarea className="input" value={form.justification} onChange={(e) => setForm({ ...form, justification: e.target.value })} placeholder="Incident or ticket reference" />
          </label>
          <Button type="submit" variant="primary" disabled={busy || !form.identity_id || !form.group_id || !form.justification}>Submit request</Button>
        </form>
      </div>
    </Page>
  );
}
