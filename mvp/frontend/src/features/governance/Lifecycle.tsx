import { FormEvent, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ListChecks } from "lucide-react";
import { HrisEvent, IdentityRow, api, fmtDate, useApi } from "../../api";
import { Badge, Button, Callout, Chip, EmptyState, Loading, Page, Segmented, Status, Tone, useConfirm, useToast, GovernanceTabs } from "../../components";

interface Step { action: string; detail: string; system: string }
interface Impact { permissions_removed: number; privileged_removed: number; systems: string[]; owned_nhis: number; violations_resolved: number }
interface PlanResp { event: HrisEvent; plan: { steps: Step[]; impact?: Impact } | null }

const ACTION: Record<string, [string, Tone]> = {
  disable_account: ["Disable account", "critical"],
  revoke_sessions: ["Revoke sessions", "critical"],
  revoke_grants: ["Revoke OAuth grants", "critical"],
  remove_grant: ["Remove grant", "warning"],
  cancel_jit: ["Cancel JIT", "warning"],
  reassign_owner: ["Reassign owner", "info"],
  rotate_secret: ["Rotate secret", "warning"],
  revoke_delegation: ["Revoke delegation", "critical"],
  reassign_reports: ["Move reports", "info"],
  create_identity: ["Create identity", "ok"],
  create_account: ["Create account", "ok"],
  add_grant: ["Add grant", "ok"],
  review_grant: ["Flag for review", "warning"],
};
const TYPE_TONE: Record<string, Tone> = { leaver: "critical", joiner: "ok", mover: "info" };
const TEAMS = ["backend", "frontend", "platform", "data", "security", "finance", "sales", "support", "people", "exec"];
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);

function Steps({ steps }: { steps: Step[] }) {
  return (
    <ol className="steps">
      {steps.map((s, i) => {
        const [label, tone] = ACTION[s.action] ?? [s.action.replace(/_/g, " "), "neutral" as Tone];
        return (
          <li key={i} className="step">
            <span className="act"><Badge tone={tone}>{label}</Badge></span>
            <span className="small grow">{s.detail}</span>
            <Chip mono>{s.system}</Chip>
          </li>
        );
      })}
    </ol>
  );
}

function Residual({ identityId }: { identityId: number }) {
  const { data } = useApi<{ steps: Step[]; impact: Impact }>(`/jml/leaver-plan/${identityId}`);
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  if (!data) return <Loading kind="block" />;
  if (!data.steps.length) return <Callout tone="ok">No residual access remains.</Callout>;
  const cleanup = async () => {
    const ok = await confirm({ title: `Run ${data.steps.length} cleanup steps?`, body: "Disables the remaining accounts, removes grants and re-homes owned machine identities.", confirmLabel: "Clean up", danger: true });
    if (ok === null) return;
    setBusy(true);
    try {
      const ev = await api<HrisEvent>("/hris/events", { type: "leaver", identity_id: identityId, payload: { reason: "Residual access cleanup" } });
      await api(`/hris/events/${ev.id}/execute`, {});
      toast("Residual access cleaned up");
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Callout tone="bad">
        <div className="spread">
          <span>The legacy offboarding missed things: {data.impact.permissions_removed} permissions across {data.impact.systems.join(", ") || "no systems"} and {data.impact.owned_nhis} owned machine identities still need attention.</span>
          <Button size="sm" variant="danger-solid" disabled={busy} onClick={cleanup}>Clean up ({data.steps.length} steps)</Button>
        </div>
      </Callout>
      <Steps steps={data.steps} />
    </>
  );
}

function Plan({ eventId }: { eventId: number }) {
  const { data, error } = useApi<PlanResp>(`/hris/events/${eventId}/plan`);
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  if (!data) return <div className="card"><Loading error={error} kind="block" /></div>;
  const { event, plan } = data;
  const execute = async () => {
    if (event.type === "leaver") {
      const ok = await confirm({ title: `Offboard ${event.identity?.name}?`, body: `Runs ${plan!.steps.length} steps across ${plan!.impact?.systems.join(", ")}. Accounts are disabled and access removed.`, confirmLabel: "Execute plan", danger: true });
      if (ok === null) return;
    }
    setBusy(true);
    try {
      await api(`/hris/events/${eventId}/execute`, {});
      toast(`${cap(event.type)} plan executed`);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="card stack">
      <div className="spread">
        <div>
          <h2>{cap(event.type)}: {event.identity?.name ?? String(event.payload.name ?? "unknown identity")}</h2>
          <div className="small muted">HRIS event {event.external_id} · effective {fmtDate(event.effective_at)}</div>
        </div>
        {plan && <Button variant={event.type === "leaver" ? "danger-solid" : "primary"} disabled={busy} onClick={execute}>Execute plan ({plan.steps.length} steps)</Button>}
      </div>
      {!plan && <Callout tone="ok">Executed {fmtDate(event.executed_at ?? event.effective_at)}{event.payload.historical ? " by the legacy manual offboarding process" : ""}.</Callout>}
      {!plan && event.type === "leaver" && event.identity && <Residual identityId={event.identity.id} />}
      {plan?.impact && (
        <div className="stat-row">
          <div className="s"><b className="tnum">{plan.impact.permissions_removed}</b><span>permissions removed</span></div>
          <div className="s"><b className="tnum">{plan.impact.privileged_removed}</b><span>privileged</span></div>
          <div className="s"><b className="tnum">{plan.impact.systems.length}</b><span>systems</span></div>
          <div className="s"><b className="tnum">{plan.impact.owned_nhis}</b><span>machine identities to re-own</span></div>
          <div className="s"><b className="tnum" style={{ color: "var(--ok)" }}>{plan.impact.violations_resolved}</b><span>violations resolved</span></div>
        </div>
      )}
      {plan && <Steps steps={plan.steps} />}
    </div>
  );
}

function Simulate({ onCreated }: { onCreated: (id: number) => void }) {
  const { data: idents } = useApi<IdentityRow[]>("/identities?type=human&status=active");
  const [type, setType] = useState<"joiner" | "mover" | "leaver">("leaver");
  const [iid, setIid] = useState("");
  const [team, setTeam] = useState("sales");
  const [name, setName] = useState("Juniper Halloway");
  const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    const payload =
      type === "joiner" ? { name, email: `${name.toLowerCase().replace(/ /g, ".")}@larkspur.example`, team, department: cap(team), title: "New hire" }
      : type === "mover" ? { to_team: team, to_department: cap(team) }
      : { reason: "Simulated" };
    try {
      const ev = await api<HrisEvent>("/hris/events", { type, identity_id: type === "joiner" ? null : Number(iid), payload });
      onCreated(ev.id);
    } catch (x) {
      setErr((x as Error).message);
    }
  };
  return (
    <form className="card stack" onSubmit={submit}>
      <h2>Simulate an HRIS event</h2>
      <Segmented label="Event type" value={type} onChange={setType} options={[["joiner", "Joiner"], ["mover", "Mover"], ["leaver", "Leaver"]]} />
      {type !== "joiner" ? (
        <label className="field">Employee
          <select className="input" value={iid} onChange={(e) => setIid(e.target.value)}>
            <option value="">Select…</option>
            {(idents ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)).map((i) => <option key={i.id} value={i.id}>{i.name}, {i.department}</option>)}
          </select>
        </label>
      ) : (
        <label className="field">Name<input className="input" value={name} onChange={(e) => setName(e.target.value)} /></label>
      )}
      {type !== "leaver" && (
        <label className="field">{type === "mover" ? "Moves to team" : "Team"}
          <select className="input" value={team} onChange={(e) => setTeam(e.target.value)}>{TEAMS.map((t) => <option key={t} value={t}>{cap(t)}</option>)}</select>
        </label>
      )}
      {err && <Callout tone="bad">{err}</Callout>}
      <Button type="submit" variant="primary" disabled={type !== "joiner" ? !iid : !name.trim()}>Create event and build plan</Button>
    </form>
  );
}

export function Lifecycle() {
  const { data, error } = useApi<HrisEvent[]>("/hris/events");
  const [params, setParams] = useSearchParams();
  const [status, setStatus] = useState<"pending" | "all">("all");
  const crumbs: [string, string?][] = [["Access"], ["Access reviews", "/governance/reviews"], ["Lifecycle"]];
  const pick = (id: number) => setParams({ event: String(id) }, { replace: true });
  if (!data) return <Page tabs={<GovernanceTabs />} title="Lifecycle" crumbs={crumbs}><Loading error={error} kind="page" /></Page>;
  const fromUrl = params.get("event") ? Number(params.get("event")) : null;
  const current = fromUrl ?? data.find((e) => e.status === "pending" && e.type === "leaver")?.id ?? data.find((e) => e.status === "pending")?.id ?? null;
  const rows = data.filter((e) => status === "all" || e.status === "pending");
  return (
    <Page tabs={<GovernanceTabs />} title="Lifecycle: joiners, movers and leavers" crumbs={crumbs} sub="Workday events drive provisioning plans across every connected system. A leaver plan also re-homes the machine identities and AI agents the person owned, and revokes delegations made on their behalf.">
      <div className="grid list-detail">
        <div className="stack">
          <div className="card flush">
            <div className="card-h">
              <h2>HRIS feed</h2>
              <Segmented label="Show" value={status} onChange={setStatus} options={[["all", "All"], ["pending", "Pending"]]} />
            </div>
            {rows.length === 0 ? <EmptyState title="No pending events" icon={<ListChecks size={18} />}>Every joiner, mover and leaver has been handled.</EmptyState> : (
              <div role="list" aria-label="HRIS events" style={{ maxHeight: 520, overflow: "auto" }}>
                {rows.map((e) => (
                  <div key={e.id} role="listitem">
                  <button type="button" aria-pressed={current === e.id} className={`qrow qbtn ${current === e.id ? "selected" : ""}`} style={{ gridTemplateColumns: "minmax(0,1fr) auto" }}
                    onClick={() => pick(e.id)}>
                    <span style={{ minWidth: 0 }}>
                      <span className="row tight"><Badge tone={TYPE_TONE[e.type]}>{cap(e.type)}</Badge> <b className="small">{e.identity?.name ?? String(e.payload.name ?? "")}</b></span>
                      <span className="q-meta">{e.payload.historical ? "Handled by legacy process" : fmtDate(e.effective_at)}</span>
                    </span>
                    <Status s={e.status} />
                  </button>
                  </div>
                ))}
              </div>
            )}
          </div>
          <Simulate onCreated={pick} />
        </div>
        <div>{current !== null ? <Plan key={current} eventId={current} /> : <div className="card"><EmptyState title="Select an event">Choose an event from the feed to see its plan.</EmptyState></div>}</div>
      </div>
    </Page>
  );
}
