import { FormEvent, useState } from "react";
import { CalendarClock, Play, Plus } from "lucide-react";
import {
  ConnectorRow, IdentityRow, Recurrence, ReviewSchedule, ReviewScheduleInput, createReviewSchedule, fmtDate, runReviewSchedule,
  updateReviewSchedule, useApi,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Drawer, EmptyState, Loading, useToast } from "../../components";

/**
 * Scheduled access reviews (issue #166). A schedule launches a scoped campaign on its recurrence,
 * reminds reviewers before the due date, and at the due date revokes what nobody decided (or
 * hands it to an escalation reviewer first).
 */
const REC_LABEL: Record<Recurrence, string> = { once: "Once", quarterly: "Every quarter", semiannual: "Every six months", annual: "Every year" };

export function ReviewSchedules({ onLaunched }: { onLaunched: (campaignId: number) => void }) {
  const { data, error, reload } = useApi<ReviewSchedule[]>("/reviews/schedules");
  const { can } = useSession();
  const manage = can("reviews.manage");
  const toast = useToast();
  const [edit, setEdit] = useState<ReviewSchedule | "new" | null>(null);
  if (!data) return <div className="card flush"><Loading error={error} /></div>;
  const run = async (s: ReviewSchedule) => {
    try {
      const l = await runReviewSchedule(s.id);
      toast(`Launched ${s.name}`);
      reload();
      onLaunched(l.campaign_id);
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  return (
    <div className="stack">
      {manage && <div className="row"><Button variant="primary" icon={<Plus size={15} />} onClick={() => setEdit("new")}>New schedule</Button></div>}
      {data.length === 0 ? (
        <div className="card"><EmptyState title="No review schedules" icon={<CalendarClock size={18} />}>
          Schedule a quarterly review of privileged access, or a yearly review of one application. Each run is a normal campaign with a due date.
        </EmptyState></div>
      ) : (
        <div className="card flush">
          <div className="table-scroll">
            <table>
              <thead><tr><th>Schedule</th><th className="hide-narrow">Scope</th><th>Next run</th><th className="hide-narrow">Last run</th><th /></tr></thead>
              <tbody>
                {data.map((s) => {
                  const last = s.launches[0];
                  return (
                    <tr key={s.id}>
                      <td>
                        <b>{s.name}</b> {!s.enabled && <Badge tone="outline">Paused</Badge>}
                        <div className="xs faint">{REC_LABEL[s.recurrence]} · {s.duration_days} days to review · {s.close_out === "revoke" ? "undecided items are revoked" : `undecided items go to ${s.escalation_reviewer?.name ?? "?"} for ${s.escalation_days} days, then are revoked`}</div>
                      </td>
                      <td className="small hide-narrow">{s.system ?? "All systems"}{s.privileged_only ? ", privileged only" : ""}</td>
                      <td className="small nowrap">{s.enabled && s.next_run_at ? fmtDate(s.next_run_at) : "—"}</td>
                      <td className="small hide-narrow">
                        {last ? <>{last.period} · {last.closed_at ? `closed${last.revoked ? `, ${last.revoked} revoked` : ""}` : `due ${fmtDate(last.due_at)}`}{last.escalated_at && " · escalated"}</> : <span className="faint">Never</span>}
                      </td>
                      <td className="actions-cell">
                        {manage && <><Button size="sm" icon={<Play size={14} />} onClick={() => run(s)}>Run now</Button>{" "}<Button size="sm" variant="ghost" onClick={() => setEdit(s)}>Edit</Button></>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {edit && <ScheduleForm schedule={edit === "new" ? null : edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload(); }} />}
    </div>
  );
}

function localInput(iso: string | null): string {
  const d = iso ? new Date(iso) : new Date(Date.now() + 864e5);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function ScheduleForm({ schedule, onClose, onSaved }: { schedule: ReviewSchedule | null; onClose: () => void; onSaved: () => void }) {
  const { data: conns } = useApi<ConnectorRow[]>("/connectors");
  const { data: people } = useApi<IdentityRow[]>("/identities?type=human");
  const toast = useToast();
  const s = schedule;
  const [f, setF] = useState({
    name: s?.name ?? "Quarterly privileged access review", system: s?.system ?? "", privileged: s?.privileged_only ?? true,
    unused: String(s?.unused_days ?? 60), duration: String(s?.duration_days ?? 14), reminder: String(s?.reminder_days ?? 3),
    closeOut: s?.close_out ?? "revoke", escalation: s?.escalation_reviewer ? String(s.escalation_reviewer.id) : "",
    escalationDays: String(s?.escalation_days ?? 7), recurrence: (s?.recurrence ?? "quarterly") as Recurrence,
    first: localInput(s?.next_run_at ?? null), enabled: s?.enabled ?? true,
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const body: ReviewScheduleInput = {
      name: f.name, system: f.system || null, privileged_only: f.privileged, unused_days: Number(f.unused), duration_days: Number(f.duration),
      reminder_days: Number(f.reminder), close_out: f.closeOut as "revoke" | "escalate", escalation_identity_id: f.escalation ? Number(f.escalation) : null,
      escalation_days: Number(f.escalationDays), recurrence: f.recurrence, first_run_at: new Date(f.first).toISOString(), enabled: f.enabled,
    };
    try {
      if (s) await updateReviewSchedule(s.id, body);
      else await createReviewSchedule(body);
      toast("Schedule saved");
      onSaved();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={s ? `Edit ${s.name}` : "New review schedule"} onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Name<input className="input" value={f.name} onChange={set("name")} required maxLength={200} /></label>
        <label className="field">Scope
          <select className="input" value={f.system} onChange={set("system")}>
            <option value="">All systems</option>
            {(conns ?? []).map((c) => <option key={c.system} value={c.system}>{c.name}</option>)}
          </select>
        </label>
        <label className="row tight small"><input type="checkbox" checked={f.privileged} onChange={(e) => setF({ ...f, privileged: e.target.checked })} /> Privileged access only</label>
        <div className="row">
          <label className="field" style={{ flex: 1 }}>Repeats
            <select className="input" value={f.recurrence} onChange={set("recurrence")}>
              {(Object.keys(REC_LABEL) as Recurrence[]).map((r) => <option key={r} value={r}>{REC_LABEL[r]}</option>)}
            </select>
          </label>
          <label className="field" style={{ flex: 1 }}>{s ? "Next run" : "First run"}<input className="input" type="datetime-local" value={f.first} onChange={set("first")} required /></label>
        </div>
        <div className="row">
          <label className="field" style={{ flex: 1 }}>Days to review<input className="input" inputMode="numeric" value={f.duration} onChange={set("duration")} /></label>
          <label className="field" style={{ flex: 1 }}>Remind, days before<input className="input" inputMode="numeric" value={f.reminder} onChange={set("reminder")} /></label>
          <label className="field" style={{ flex: 1 }}>Flag unused after (days)<input className="input" inputMode="numeric" value={f.unused} onChange={set("unused")} /></label>
        </div>
        <label className="field">At the due date, undecided items
          <select className="input" value={f.closeOut} onChange={set("closeOut")}>
            <option value="revoke">are revoked</option>
            <option value="escalate">go to an escalation reviewer, then are revoked</option>
          </select>
        </label>
        {f.closeOut === "escalate" && (
          <div className="row">
            <label className="field" style={{ flex: 2 }}>Escalation reviewer
              <select className="input" value={f.escalation} onChange={set("escalation")} required>
                <option value="">Choose a person…</option>
                {(people ?? []).filter((p) => p.status === "active").map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </label>
            <label className="field" style={{ flex: 1 }}>For (days)<input className="input" inputMode="numeric" value={f.escalationDays} onChange={set("escalationDays")} /></label>
          </div>
        )}
        <label className="row tight small"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled</label>
        <p className="small muted">Reviewers are each person's manager, or the owner for machine identities, falling back to the security lead. Reminders are recorded in the audit log until notifications ship (#168).</p>
        {error && <Callout tone="bad">{error}</Callout>}
        <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}
