/**
 * Identity lifecycle pieces (issue #159) shared by the Contractors & guests page and the identity
 * panel: the lifecycle summary with its history, and the drawers that set or extend a term.
 */
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { CalendarClock, CalendarPlus, Pencil } from "lucide-react";
import { IdentityRow, Lifecycle, LifecycleSpec, WORKER_TYPES, WorkerType, fmtDate, fmtDay, lifecycle, relTime, useApi } from "../../api";
import { Badge, Button, Callout, Drawer, Loading, useToast } from "../../components";

export const WORKER_LABEL: Record<WorkerType, string> = {
  employee: "Employee", contractor: "Contractor", intern: "Intern", partner: "Partner", vendor: "Vendor", guest: "Guest",
};

export function StateBadge({ l }: { l: Lifecycle }) {
  switch (l.state) {
    case "ended":
      return <Badge>Ended</Badge>;
    case "upcoming":
      return <Badge tone="info">Starts {fmtDay(l.starts_at)}</Badge>;
    case "ending":
      return <Badge tone={(l.days_left ?? 0) <= 3 ? "critical" : "warning"} dot>{l.days_left === 0 ? "Ends today" : `Ends in ${l.days_left} day${l.days_left === 1 ? "" : "s"}`}</Badge>;
  }
  return l.ends_at ? <Badge tone="ok" dot>Active</Badge> : <span className="small faint">No end date</span>;
}

const toDateInput = (s: string | null) => (s ? s.slice(0, 10) : "");
/** A date input's day, as the end of that day in UTC. */
const endOfDay = (d: string) => (d ? new Date(`${d}T23:59:59Z`).toISOString() : null);
const startOfDay = (d: string) => (d ? new Date(`${d}T00:00:00Z`).toISOString() : null);

/** The lifecycle block of a person: worker type, sponsor, dates, actions and history. */
export function LifecycleSection({ id, compact }: { id: number; compact?: boolean }) {
  const { data: l, error } = useApi<Lifecycle>(lifecycle.paths.one(id));
  const [drawer, setDrawer] = useState<null | "set" | "extend">(null);
  if (!l) return <Loading error={error} kind="block" />;
  return (
    <section className="stack-sm" aria-labelledby={`lc-${id}`}>
      <div className="spread">
        <h3 id={`lc-${id}`} style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Worker type and dates</h3>
        <span className="row tight">
          {l.can_extend && <Button size="sm" icon={<CalendarPlus size={14} />} onClick={() => setDrawer("extend")}>Extend</Button>}
          {l.can_manage && l.state !== "ended" && <Button size="sm" icon={<Pencil size={14} />} onClick={() => setDrawer("set")}>{l.default ? "Set" : "Change"}</Button>}
        </span>
      </div>
      <dl className="kv">
        <dt>Worker type</dt><dd>{WORKER_LABEL[l.worker_type]}{l.source === "hris" && <span className="xs faint"> · from the HRIS</span>}</dd>
        {l.organization && <><dt>Organization</dt><dd>{l.organization}</dd></>}
        {!l.default && <><dt>Sponsor</dt><dd>{l.sponsor ? <Link to={`/directory/people?selected=${l.sponsor.id}`}>{l.sponsor.name}</Link> : <span className="faint">None</span>}</dd></>}
        {l.starts_at && <><dt>Starts</dt><dd>{fmtDay(l.starts_at)}</dd></>}
        <dt>Ends</dt><dd>{l.ends_at ? <>{fmtDay(l.ends_at)} <StateBadge l={l} /></> : <span className="faint">No end date</span>}</dd>
      </dl>
      {l.state === "ending" && <Callout tone="warn">On the end date Tessera runs the leaver plan: accounts are disabled, grants removed and ownership reassigned. {l.sponsor ? `${l.sponsor.name} can extend it.` : ""}</Callout>}
      {!compact && (l.events?.length ?? 0) > 0 && (
        <ol className="timeline">
          {l.events!.map((e, i) => (
            <li key={i}>
              <b>{e.event[0].toUpperCase() + e.event.slice(1)}</b> by {e.actor} <span className="faint" title={fmtDate(e.at)}>{relTime(e.at)}</span>
              {e.ends_at && <span className="small muted"> · ends {fmtDay(e.ends_at)}</span>}
              {e.note && <div className="small muted">{e.note}</div>}
            </li>
          ))}
        </ol>
      )}
      {drawer === "set" && <SetLifecycleDrawer id={id} current={l} onClose={() => setDrawer(null)} />}
      {drawer === "extend" && <ExtendDrawer l={l} onClose={() => setDrawer(null)} />}
    </section>
  );
}

/** Set or change a person's worker type, sponsor and dates (lifecycle.manage). */
export function SetLifecycleDrawer({ id, current, onClose }: { id?: number; current?: Lifecycle; onClose: () => void }) {
  const { data: people } = useApi<IdentityRow[]>("/identities?type=human&status=active");
  const toast = useToast();
  const [pid, setPid] = useState<number | "">(id ?? "");
  const [f, setF] = useState(() => ({
    worker_type: (current && !current.default ? current.worker_type : "contractor") as WorkerType,
    sponsor: current?.sponsor?.id ?? ("" as number | ""),
    organization: current?.organization ?? "",
    starts: toDateInput(current?.starts_at ?? null),
    ends: toDateInput(current?.ends_at ?? null),
    reason: "",
  }));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setErr(null), [f]);
  const employee = f.worker_type === "employee";
  const sponsors = useMemo(() => (people ?? []).filter((p) => p.id !== pid), [people, pid]);
  const ready = pid !== "" && f.reason.trim() !== "" && (employee || (f.ends !== "" && f.sponsor !== ""));
  const save = async () => {
    setBusy(true);
    try {
      const spec: LifecycleSpec = {
        worker_type: f.worker_type, sponsor_identity_id: f.sponsor === "" ? null : Number(f.sponsor),
        organization: f.organization.trim() || null, starts_at: startOfDay(f.starts), ends_at: endOfDay(f.ends), reason: f.reason.trim(),
      };
      const l = await lifecycle.set(Number(pid), spec);
      toast(`${l.person.name} is now ${WORKER_LABEL[l.worker_type].toLowerCase()}${l.ends_at ? `, ending ${fmtDay(l.ends_at)}` : ""}`);
      onClose();
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={current?.person ? `Worker type and dates: ${current.person.name}` : "Add a contractor or guest"} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" onClick={save} disabled={!ready || busy}>Save</Button></>}>
      <div className="stack">
        {id == null && (
          <label className="field">Person
            <select className="input" data-autofocus value={pid} onChange={(e) => setPid(e.target.value ? Number(e.target.value) : "")}>
              <option value="">Choose…</option>
              {(people ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}{p.department ? ` (${p.department})` : ""}</option>)}
            </select>
          </label>
        )}
        <div className="grid g2">
          <label className="field">Worker type
            <select className="input" value={f.worker_type} onChange={(e) => setF({ ...f, worker_type: e.target.value as WorkerType })}>
              {WORKER_TYPES.map((w) => <option key={w} value={w}>{WORKER_LABEL[w]}</option>)}
            </select>
          </label>
          <label className="field">Organization<input className="input" value={f.organization} onChange={(e) => setF({ ...f, organization: e.target.value })} placeholder="e.g. Northwind Consulting" /></label>
        </div>
        <label className="field">Sponsor{employee ? " (optional)" : ""}
          <select className="input" value={f.sponsor} onChange={(e) => setF({ ...f, sponsor: e.target.value ? Number(e.target.value) : "" })}>
            <option value="">{employee ? "None" : "Choose the employee accountable for them…"}</option>
            {sponsors.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </label>
        <div className="grid g2">
          <label className="field">Starts (optional)<input className="input" type="date" value={f.starts} onChange={(e) => setF({ ...f, starts: e.target.value })} /></label>
          <label className="field">Ends{employee ? " (optional)" : ""}<input className="input" type="date" value={f.ends} onChange={(e) => setF({ ...f, ends: e.target.value })} /></label>
        </div>
        <p className="xs faint">Non-employees need a sponsor and an end date at most a year away. Warnings go to the sponsor 14, 7 and 1 days before; on the end date the leaver plan runs.</p>
        <label className="field">Reason (kept in the history and the audit log)<textarea className="input" value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}

/** Move an end date later (the sponsor, or lifecycle.manage). */
export function ExtendDrawer({ l, onClose }: { l: Lifecycle; onClose: () => void }) {
  const toast = useToast();
  const [ends, setEnds] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const min = toDateInput(l.ends_at);
  const go = async () => {
    setBusy(true);
    try {
      const r = await lifecycle.extend(l.person.id, endOfDay(ends)!, reason.trim());
      toast(`${r.person.name}'s term now ends ${fmtDay(r.ends_at)}`);
      onClose();
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={`Extend ${l.person.name}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" icon={<CalendarClock size={14} />} onClick={go} disabled={!ends || !reason.trim() || busy}>Extend</Button></>}>
      <div className="stack">
        <p className="muted">Currently ends {fmtDay(l.ends_at)}. The new end date is at most a year from today; the warnings start again.</p>
        <label className="field">New end date<input className="input" type="date" data-autofocus min={min} value={ends} onChange={(e) => setEnds(e.target.value)} /></label>
        <label className="field">Reason<textarea className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. statement of work renewed to March" /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}
