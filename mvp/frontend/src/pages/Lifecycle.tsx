import { useState } from "react";
import { api, fmtDate, useApi } from "../api";
import { IdLink, Loading, Page } from "../components/ui";

const ACTION: Record<string, [string, string]> = {
  disable_account: ["Disable account", "bad"],
  remove_grant: ["Remove grant", "warn"],
  cancel_jit: ["Cancel JIT", "warn"],
  reassign_owner: ["Reassign owner", "info"],
  rotate_secret: ["Rotate secret", "medium"],
  revoke_delegation: ["Revoke delegation", "bad"],
  reassign_reports: ["Move reports", "info"],
  create_identity: ["Create identity", "ok"],
  create_account: ["Create account", "ok"],
  add_grant: ["Add grant", "ok"],
  review_grant: ["Flag for review", "medium"],
};
const TEAMS = ["backend", "frontend", "platform", "data", "security", "finance", "sales", "support", "people", "exec"];

function Residual({ identityId, onDone }: { identityId: number; onDone: () => void }) {
  const { data, reload } = useApi<any>(`/jml/leaver-plan/${identityId}`);
  const [busy, setBusy] = useState(false);
  if (!data) return null;
  const cleanup = async () => {
    setBusy(true);
    const ev = await api<any>("/hris/events", { type: "leaver", identity_id: identityId, payload: { reason: "Residual access cleanup" } });
    await api(`/hris/events/${ev.id}/execute`, {});
    setBusy(false);
    reload();
    onDone();
  };
  if (!data.steps.length) return <div className="callout ok">No residual access remains.</div>;
  return (
    <>
      <div className="callout bad spread">
        <span>The legacy offboarding missed things: {data.impact.permissions_removed} effective permission(s) across {data.impact.systems.join(", ") || "no systems"} and {data.impact.owned_nhis} owned NHI(s) still need attention.</span>
        <button className="danger solid sm" disabled={busy} onClick={cleanup}>Clean up ({data.steps.length} steps)</button>
      </div>
      <Steps steps={data.steps} />
    </>
  );
}

function Steps({ steps }: { steps: any[] }) {
  return (
    <ul className="steps">
      {steps.map((s: any, i: number) => {
        const [label, cls] = ACTION[s.action] ?? [s.action, ""];
        return (
          <li key={i} className="step">
            <span className="act"><span className={`badge ${cls}`}>{label}</span></span>
            <span className="small">{s.detail}</span>
            <span className="chip sys" style={{ marginLeft: "auto" }}>{s.system}</span>
          </li>
        );
      })}
    </ul>
  );
}

function Plan({ eventId, onDone }: { eventId: number; onDone: () => void }) {
  const { data, error, reload } = useApi<any>(`/hris/events/${eventId}/plan`);
  const [busy, setBusy] = useState(false);
  if (!data) return <Loading error={error} />;
  const { event, plan } = data;
  const execute = async () => {
    setBusy(true);
    await api(`/hris/events/${eventId}/execute`, {});
    setBusy(false);
    reload();
    onDone();
  };
  return (
    <div className="card stack">
      <div className="spread">
        <div>
          <h2 style={{ margin: 0 }}>{event.type[0].toUpperCase() + event.type.slice(1)}: {event.identity?.name ?? event.payload.name}</h2>
          <div className="small muted">HRIS event {event.external_id} · effective {fmtDate(event.effective_at)}</div>
        </div>
        {plan && <button className="primary" disabled={busy} onClick={execute}>Execute plan ({plan.steps.length} steps)</button>}
      </div>
      {!plan && <div className="callout ok">Executed {fmtDate(event.executed_at ?? event.effective_at)}{event.payload.historical ? " by the legacy (manual) offboarding process" : ""}.</div>}
      {!plan && event.type === "leaver" && event.identity && <Residual identityId={event.identity.id} onDone={onDone} />}
      {plan?.impact && (
        <div className="stat-row">
          <div className="s"><b>{plan.impact.permissions_removed}</b><span>permissions removed</span></div>
          <div className="s"><b>{plan.impact.privileged_removed}</b><span>privileged</span></div>
          <div className="s"><b>{plan.impact.systems.length}</b><span>systems</span></div>
          <div className="s"><b>{plan.impact.owned_nhis}</b><span>NHIs / agents to re-own</span></div>
          <div className="s"><b style={{ color: "var(--ok)" }}>{plan.impact.violations_resolved}</b><span>violations resolved</span></div>
        </div>
      )}
      {plan && <Steps steps={plan.steps} />}
    </div>
  );
}

function Simulate({ onCreated }: { onCreated: (id: number) => void }) {
  const { data: idents } = useApi<any[]>("/identities?type=human&status=active");
  const [type, setType] = useState("leaver");
  const [iid, setIid] = useState("");
  const [team, setTeam] = useState("sales");
  const [name, setName] = useState("Juniper Halloway");
  const [err, setErr] = useState<string | null>(null);
  const submit = async () => {
    setErr(null);
    const payload =
      type === "joiner"
        ? { name, email: `${name.toLowerCase().replace(/ /g, ".")}@larkspur.example`, team, department: team[0].toUpperCase() + team.slice(1), title: "New hire" }
        : type === "mover"
          ? { to_team: team, to_department: team[0].toUpperCase() + team.slice(1) }
          : { reason: "Simulated" };
    try {
      const ev = await api<any>("/hris/events", { type, identity_id: type === "joiner" ? null : Number(iid), payload });
      onCreated(ev.id);
    } catch (e: any) {
      setErr(e.message);
    }
  };
  return (
    <div className="card stack">
      <h2>Simulate an HRIS event</h2>
      <div className="seg">
        {["joiner", "mover", "leaver"].map((t) => <button key={t} className={type === t ? "on" : ""} onClick={() => setType(t)}>{t}</button>)}
      </div>
      {type !== "joiner" ? (
        <label className="f">Employee
          <select value={iid} onChange={(e) => setIid(e.target.value)}>
            <option value="">Select…</option>
            {(idents ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)).map((i) => <option key={i.id} value={i.id}>{i.name} — {i.department}</option>)}
          </select>
        </label>
      ) : (
        <label className="f">Name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
      )}
      {type !== "leaver" && (
        <label className="f">{type === "mover" ? "Moves to team" : "Team"}
          <select value={team} onChange={(e) => setTeam(e.target.value)}>{TEAMS.map((t) => <option key={t}>{t}</option>)}</select>
        </label>
      )}
      {err && <div className="err">{err}</div>}
      <button className="primary" disabled={type !== "joiner" && !iid} onClick={submit}>Emit event & build plan</button>
    </div>
  );
}

export default function Lifecycle() {
  const { data, error, reload } = useApi<any[]>("/hris/events");
  const [sel, setSel] = useState<number | null>(null);
  if (!data) return <Loading error={error} />;
  const current = sel ?? data.find((e) => e.status === "pending" && e.type === "leaver")?.id ?? data.find((e) => e.status === "pending")?.id ?? null;
  return (
    <Page title="Joiner / mover / leaver" sub="Workday (HRIS) events drive provisioning plans across every connected system. A leaver plan also re-homes the NHIs and AI agents the person owned and revokes delegations made on their behalf.">
      <div className="grid" style={{ gridTemplateColumns: "340px 1fr" }}>
        <div className="stack">
          <div className="card flush">
            <div className="card-h"><h2>HRIS feed</h2></div>
            <table>
              <tbody>
                {data.map((e) => (
                  <tr key={e.id} className="click" onClick={() => setSel(e.id)} style={current === e.id ? { background: "var(--brand-2)" } : undefined}>
                    <td>
                      <span className={`badge ${e.type === "leaver" ? "bad" : e.type === "joiner" ? "ok" : "info"}`}>{e.type}</span>{" "}
                      {e.identity ? <IdLink i={e.identity} /> : <b>{e.payload.name}</b>}
                      <div className="small faint">{e.payload.historical ? "handled by legacy process" : fmtDate(e.effective_at)}</div>
                    </td>
                    <td className="num"><span className={`badge ${e.status === "pending" ? "medium" : ""}`}>{e.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Simulate onCreated={(id) => { reload(); setSel(id); }} />
        </div>
        <div>{current !== null ? <Plan key={current} eventId={current} onDone={reload} /> : <div className="card empty">Select an event.</div>}</div>
      </div>
    </Page>
  );
}
