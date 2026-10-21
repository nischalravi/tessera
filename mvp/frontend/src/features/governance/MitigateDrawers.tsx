/**
 * Drawers for remediating one SoD violation (issue #298): mitigate with a control or accept until a
 * date (a request another person must approve), and escalate to the risk owner. Used from the SoD
 * conflict panel and from access reviews. The server refuses an option the risk does not offer.
 */
import { FormEvent, useMemo, useState } from "react";
import { SodControlList, SodMitigationList, sodControlPaths, sodMitigations, sodRemediate, useApi } from "../../api";
import { Button, Callout, Drawer, Loading, useToast } from "../../components";
import { defaultEndDay, endDayError, latestEndDay, parseEvidence } from "./sodModel";

/** The violation a drawer acts on. */
export interface Target { riskId: string; riskName: string; identityId: number; identityName: string }

export function MitigateDrawer({ target, kind: initial = "control", offerControl = true, offerAccept = true, onClose, onDone }: {
  target: Target; kind?: "control" | "accept"; offerControl?: boolean; offerAccept?: boolean; onClose: () => void; onDone: () => void;
}) {
  const toast = useToast();
  const { data: lib } = useApi<SodControlList>(sodControlPaths.controls);
  const { data: lim } = useApi<SodMitigationList>(sodControlPaths.mitigations({ status: "active" }));
  const now = useMemo(() => new Date(), []);
  const maxDays = lim?.max_days ?? 365;
  const [kind, setKind] = useState<"control" | "accept">(initial);
  const [control, setControl] = useState("");
  const [why, setWhy] = useState("");
  const [end, setEnd] = useState(() => defaultEndDay(now, 365));
  const [evidence, setEvidence] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const controls = (lib?.controls ?? []).filter((c) => c.status === "active");
  const dateErr = endDayError(end, now, maxDays);
  const ready = !busy && why.trim() !== "" && !dateErr && (kind === "accept" || control !== "");
  const selected = controls.find((c) => c.id === control);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setErr(null);
    try {
      await sodMitigations.request({ risk_id: target.riskId, identity_id: target.identityId, kind, ...(kind === "control" ? { control_id: control } : {}),
        justification: why.trim(), ends_at: end, evidence: parseEvidence(evidence) });
      toast("Requested. Another person must approve it before it covers the violation.");
      onDone();
      onClose();
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={kind === "control" ? "Mitigate with a control" : "Accept until a date"} sub={`${target.identityName}: ${target.riskName}`} onClose={onClose} wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="sod-mit-form" variant="primary" disabled={!ready}>Request approval</Button></>}>
      <form id="sod-mit-form" className="stack" onSubmit={submit}>
        {offerControl && offerAccept && (
          <fieldset className="row" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="small muted">How</legend>
            <label className="row tight small"><input type="radio" name="kind" checked={kind === "control"} onChange={() => setKind("control")} /> Mitigating control</label>
            <label className="row tight small"><input type="radio" name="kind" checked={kind === "accept"} onChange={() => setKind("accept")} /> Accept the risk</label>
          </fieldset>
        )}
        {kind === "control" && (
          !lib ? <Loading kind="block" /> : (
            <label className="field">Control
              <select className="input" value={control} onChange={(e) => setControl(e.target.value)} data-autofocus>
                <option value="">Select…</option>
                {controls.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.type}, {c.frequency})</option>)}
              </select>
            </label>
          )
        )}
        {selected?.evidence_requirement && <Callout tone="neutral">This control needs evidence: {selected.evidence_requirement}</Callout>}
        {kind === "control" && lib && controls.length === 0 && <Callout tone="warn">The control library is empty. A policy admin adds controls under Protection → Mitigating controls.</Callout>}
        <label className="field">Justification<textarea className="input" value={why} onChange={(e) => setWhy(e.target.value)} maxLength={2000} placeholder="Why this is acceptable, and what covers it" /></label>
        <label className="field">Ends on (required)
          <input className="input" type="date" value={end} onChange={(e) => setEnd(e.target.value)} max={latestEndDay(now, maxDays)} aria-invalid={!!dateErr} aria-describedby="sod-end-help" />
        </label>
        <p id="sod-end-help" className={dateErr ? "small" : "small muted"} role={dateErr ? "alert" : undefined}>{dateErr ?? `At most ${maxDays} days. When it ends the violation opens again.`}</p>
        <label className="field">Evidence references (one per line, optional)<textarea className="input" rows={3} value={evidence} onChange={(e) => setEvidence(e.target.value)} placeholder="Ticket, document or report links" /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

export function EscalateDrawer({ target, routeTo, onClose, onDone }: { target: Target; /** Who it goes to, when known (the ruleset's approver or the risk owner). */ routeTo?: string | null; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!note.trim() || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const sent = await sodRemediate.escalate(target.riskId, target.identityId, note.trim());
      toast(sent.routed_to ? `Sent to ${sent.routed_to.name}, who has an inbox item` : "Sent to the approver");
      onDone();
      onClose();
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={routeTo ? `Escalate to ${routeTo}` : "Escalate to the approver"} sub={`${target.identityName}: ${target.riskName}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="sod-esc-form" variant="primary" disabled={!note.trim() || busy}>Send</Button></>}>
      <form id="sod-esc-form" className="stack" onSubmit={submit}>
        <p className="small muted">{routeTo ? `${routeTo} gets an inbox item` : "The ruleset's approver, or the owner of the risk, gets an inbox item"} and can decide: revoke, mitigate or accept.</p>
        <label className="field">Note<textarea className="input" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} data-autofocus /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

/** End an active mitigation early (the risk owner or an approver): the violation is open again. */
export function EndEarlyDrawer({ mitigationId, label, onClose, onDone }: { mitigationId: string; label: string; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!reason.trim() || busy) return;
    setBusy(true);
    setErr(null);
    try {
      await sodMitigations.revoke(mitigationId, reason.trim());
      toast("Ended. The violation is open again.");
      onDone();
      onClose();
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title="End the mitigation early" sub={label} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="sod-end-form" variant="danger" disabled={!reason.trim() || busy}>End it now</Button></>}>
      <form id="sod-end-form" className="stack" onSubmit={submit}>
        <p className="small muted">The violation counts as open again from now on. This is recorded in the audit log.</p>
        <label className="field">Reason<input className="input" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} data-autofocus /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}
