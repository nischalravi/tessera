/**
 * Protection → Mitigating controls (issue #298): the control library, and the mitigations that
 * apply a control (or an acceptance) to one person's violation of one risk. Another person approves
 * each one; every one has an end date, after which the violation opens again.
 */
import { FormEvent, useEffect, useState } from "react";
import { Archive, Check, History, Pencil, Plus, Undo2, X } from "lucide-react";
import {
  IdentityRow, SodControl, SodControlList, SodControlSpec, SodMitigation, SodMitigationList, SodMitigationStatus, fmtDate, fmtDay, relTime,
  sodControlPaths, sodControls, sodMitigations, useApi,
} from "../../api";
import { Badge, Button, Callout, CommandBar, DataTable, Drawer, EmptyState, Page, SidePanel, Sev, Tabs, useSelected, useToast } from "../../components";
import { EndEarlyDrawer } from "./MitigateDrawers";
import { canDecide, daysLeftLabel, expiringSoon, mitigationStatusLabel } from "./sodModel";

const I = 16;
type View = "mitigations" | "library";

const TONE: Record<SodMitigationStatus, "ok" | "warning" | "critical" | "neutral" | "info"> = {
  active: "ok", pending: "warning", rejected: "neutral", cancelled: "neutral", expired: "critical", revoked: "critical",
};

export function Mitigations() {
  const [view, setView] = useState<View>("mitigations");
  const tabs = (
    <Tabs<View> label="Mitigating controls" value={view} onChange={setView} tabs={[{ id: "mitigations", label: "Mitigations" }, { id: "library", label: "Control library" }]} />
  );
  return (
    <Page title="Mitigating controls" crumbs={[["Protection"], ["Mitigating controls"]]} tabs={tabs}
      sub={view === "library" ? "Controls that cover a separation-of-duties violation: who owns each, how often it runs and what evidence it needs." : "A mitigation applies a control, or an acceptance, to one person's violation until an end date. Another person approves it; when it ends the violation opens again."}>
      {view === "mitigations" ? <MitigationList /> : <Library />}
    </Page>
  );
}

// ------------------------------------------------------------------ mitigations

function MitigationList() {
  const { data, error, reload } = useApi<SodMitigationList>(sodControlPaths.mitigations());
  const [selected, setSelected] = useSelected();
  const rows = data?.mitigations ?? null;
  const open = rows?.find((m) => m.id === selected);
  const warn = data?.warn_days ?? 14;
  return (
    <>
      <DataTable
        id="sod-mitigations"
        rows={rows}
        error={error}
        rowKey={(m) => m.id}
        columns={[
          { id: "who", header: "Person and risk", sort: (m) => m.identity.name, cell: (m) => <div><span className="name-link">{m.identity.name}</span><div className="xs faint">{m.risk.name}</div></div> },
          { id: "priority", header: "Priority", sort: (m) => m.risk.priority, cell: (m) => <Sev s={m.risk.priority} />, hideNarrow: true },
          { id: "how", header: "Covered by", sort: (m) => m.control?.name ?? "Accepted", cell: (m) => m.control?.name ?? <span className="small">Accepted risk</span>, hideNarrow: true },
          { id: "status", header: "Status", sort: (m) => m.status, csv: (m) => m.status, cell: (m) => <Badge tone={TONE[m.status]}>{mitigationStatusLabel(m)}</Badge> },
          { id: "ends", header: "Ends", sort: (m) => m.ends_at, csv: (m) => m.ends_at, cell: (m) => <span className="small nowrap" title={fmtDate(m.ends_at)}>{fmtDay(m.ends_at)}{m.days_left !== null && <span className="xs faint" style={{ display: "block" }}>{daysLeftLabel(m.days_left)}</span>}</span> },
        ]}
        initialSort={["ends", 1]}
        searchText={(m) => `${m.identity.name} ${m.risk.name} ${m.control?.name ?? ""} ${m.justification}`}
        searchPlaceholder="Search mitigations…"
        filters={[
          { id: "status", label: "Status", options: ["pending", "active", "expired", "revoked", "rejected", "cancelled"].map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) })), get: (m) => m.status },
          { id: "soon", label: "Expiring soon", options: [{ value: "yes", label: `Within ${warn} days` }], get: (m) => (expiringSoon(m, warn) ? "yes" : "no") },
        ]}
        onRefresh={reload}
        rowLabel={(m) => `${m.identity.name}: ${m.risk.name}`}
        onRowClick={(m) => setSelected(m.id)}
        activeKey={selected}
        empty={<EmptyState title="No mitigations">Mitigate a violation from Insights → SoD conflicts. It needs a control, an end date and a second person's approval.</EmptyState>}
      />
      {open && data && <MitigationPanel m={open} list={data} onClose={() => setSelected(null)} onChanged={reload} />}
    </>
  );
}

function MitigationPanel({ m, list, onClose, onChanged }: { m: SodMitigation; list: SodMitigationList; onClose: () => void; onChanged: () => void }) {
  const toast = useToast();
  const [drawer, setDrawer] = useState<null | "reject" | "end">(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => setErr(null), [m.id]);
  const act = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      toast(done);
      onChanged();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const decide = canDecide(m, list.can_approve);
  return (
    <>
      <SidePanel title={m.identity.name} sub={<><Badge tone={TONE[m.status]}>{mitigationStatusLabel(m)}</Badge> {m.days_left !== null && <span className="small muted">{daysLeftLabel(m.days_left)}</span>}</>} onClose={onClose}
        fullHref={`/insights/sod?selected=${encodeURIComponent(`${m.risk.key}:${m.identity.id}`)}`} fullLabel="Open the conflict"
        commands={<CommandBar label={`Actions for ${m.identity.name}`} items={[
          decide && { label: "Approve", icon: <Check size={I} />, disabled: busy, onClick: () => act(() => sodMitigations.approve(m.id), "Approved. The violation is covered until its end date.") },
          decide && { label: "Reject…", icon: <X size={I} />, onClick: () => setDrawer("reject") },
          m.status === "pending" && m.requested_by_me && { label: "Withdraw", icon: <Undo2 size={I} />, disabled: busy, onClick: () => act(() => sodMitigations.cancel(m.id), "Request withdrawn") },
          m.status === "active" && list.can_approve && { label: "End early…", icon: <Archive size={I} />, danger: true, onClick: () => setDrawer("end") },
        ]} />}>
        <div className="stack">
          {err && <Callout tone="bad">{err}</Callout>}
          {m.status === "pending" && m.requested_by_me && <Callout tone="neutral">You requested this. Another person has to approve it.</Callout>}
          <div><b>{m.risk.name}</b> <Sev s={m.risk.priority} /></div>
          <dl className="kv">
            <dt>Covered by</dt><dd>{m.control?.name ?? "Accepted risk"}</dd>
            <dt>Ends</dt><dd title={fmtDate(m.ends_at)}>{fmtDay(m.ends_at)}</dd>
            <dt>Requested</dt><dd title={fmtDate(m.requested_at)}>{relTime(m.requested_at)} by {m.requested_by.display_name}</dd>
            {m.decided_by && <><dt>Decided</dt><dd title={fmtDate(m.decided_at)}>{m.status === "rejected" ? "Rejected" : "Approved"} by {m.decided_by.display_name}{m.decision_note && `: ${m.decision_note}`}</dd></>}
            {m.revoked_by && <><dt>Ended early</dt><dd>by {m.revoked_by.display_name}: {m.revoke_reason}</dd></>}
          </dl>
          <div><div className="small muted">Justification</div><p>{m.justification}</p></div>
          {m.evidence.length > 0 && <div><div className="small muted">Evidence</div><ul>{m.evidence.map((e, i) => <li key={i} className="small">{e}</li>)}</ul></div>}
        </div>
      </SidePanel>
      {drawer === "reject" && <RejectDrawer m={m} onClose={() => setDrawer(null)} onDone={onChanged} />}
      {drawer === "end" && <EndEarlyDrawer mitigationId={m.id} label={`${m.identity.name}: ${m.risk.name}`} onClose={() => setDrawer(null)} onDone={onChanged} />}
    </>
  );
}

function RejectDrawer({ m, onClose, onDone }: { m: SodMitigation; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const go = async (e: FormEvent) => {
    e.preventDefault();
    if (!note.trim() || busy) return;
    setBusy(true);
    try {
      await sodMitigations.reject(m.id, note.trim());
      toast("Rejected");
      onDone();
      onClose();
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title="Reject the request" sub={`${m.identity.name}: ${m.risk.name}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="sod-rej-form" variant="danger" disabled={!note.trim() || busy}>Reject</Button></>}>
      <form id="sod-rej-form" className="stack" onSubmit={go}>
        <label className="field">Why<input className="input" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} data-autofocus /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

// ------------------------------------------------------------------ library

function Library() {
  const { data, error, reload } = useApi<SodControlList>(sodControlPaths.controls);
  const [selected, setSelected] = useSelected();
  const [drawer, setDrawer] = useState<null | "new">(null);
  const rows = data?.controls ?? null;
  const open = rows?.find((c) => c.id === selected);
  return (
    <>
      <DataTable
        id="sod-controls"
        rows={rows}
        error={error}
        rowKey={(c) => c.id}
        columns={[
          { id: "name", header: "Control", sort: (c) => c.name, cell: (c) => <div><span className="name-link">{c.name}</span><div className="xs faint truncate" style={{ maxWidth: 520 }}>{c.description}</div></div> },
          { id: "type", header: "Type", sort: (c) => c.type, cell: (c) => <span className="small">{c.type}</span> },
          { id: "freq", header: "Frequency", sort: (c) => c.frequency, cell: (c) => <span className="small">{c.frequency}</span>, hideNarrow: true },
          { id: "owner", header: "Owner", sort: (c) => c.owner?.name ?? "", cell: (c) => c.owner?.name ?? <span className="faint">None</span>, hideNarrow: true },
          { id: "uses", header: "In use", num: true, sort: (c) => c.active_mitigations, cell: (c) => c.active_mitigations },
          { id: "status", header: "Status", sort: (c) => c.status, cell: (c) => (c.status === "retired" ? <Badge>Retired</Badge> : <span className="small faint">Active</span>) },
        ]}
        searchText={(c) => `${c.name} ${c.description} ${c.owner?.name ?? ""}`}
        searchPlaceholder="Search controls…"
        filters={[
          { id: "type", label: "Type", options: (data?.types ?? []).map((t) => ({ value: t, label: t[0].toUpperCase() + t.slice(1) })), get: (c) => c.type },
          { id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "retired", label: "Retired" }], get: (c) => c.status },
        ]}
        commands={[data?.can_manage && { label: "New control", icon: <Plus size={I} />, onClick: () => setDrawer("new") }]}
        onRefresh={reload}
        rowLabel={(c) => c.name}
        onRowClick={(c) => setSelected(c.id)}
        activeKey={selected}
        empty={<EmptyState title="No controls yet">A control is something that covers a violation, such as a monthly review of payments. Add one, then mitigate violations with it.</EmptyState>}
      />
      {open && data && <ControlPanel c={open} canManage={data.can_manage} onClose={() => setSelected(null)} onChanged={reload} />}
      {drawer === "new" && data && <ControlEditor lists={data} onClose={() => setDrawer(null)} onSaved={(c) => { reload(); setSelected(c.id); }} />}
    </>
  );
}

function ControlPanel({ c, canManage, onClose, onChanged }: { c: SodControl; canManage: boolean; onClose: () => void; onChanged: () => void }) {
  const { data } = useApi<SodControlList>(sodControlPaths.controls);
  const [drawer, setDrawer] = useState<null | "edit" | "retire">(null);
  const manage = canManage && c.status === "active";
  return (
    <>
      <SidePanel title={c.name} sub={c.status === "retired" ? <Badge>Retired</Badge> : <Badge tone="info">Version {c.version}</Badge>} onClose={onClose}
        commands={<CommandBar label={`Actions for ${c.name}`} items={[
          manage && { label: "Edit", icon: <Pencil size={I} />, onClick: () => setDrawer("edit") },
          manage && { label: "Retire", icon: <Archive size={I} />, danger: true, onClick: () => setDrawer("retire") },
        ]} />}>
        <div className="stack">
          <p className="muted">{c.description || <span className="faint">No description</span>}</p>
          <dl className="kv">
            <dt>Type</dt><dd>{c.type}</dd>
            <dt>Frequency</dt><dd>{c.frequency}</dd>
            <dt>Owner</dt><dd>{c.owner?.name ?? <span className="faint">None</span>}</dd>
            <dt>Evidence needed</dt><dd>{c.evidence_requirement || <span className="faint">None stated</span>}</dd>
            <dt>Covering now</dt><dd>{c.active_mitigations} violation{c.active_mitigations === 1 ? "" : "s"}</dd>
            <dt>Updated</dt><dd title={fmtDate(c.updated_at)}>{relTime(c.updated_at)}{c.updated_by && ` by ${c.updated_by.display_name}`}</dd>
          </dl>
          <p className="xs faint"><History size={12} aria-hidden /> Changes are kept in the audit log.</p>
        </div>
      </SidePanel>
      {drawer === "edit" && data && <ControlEditor control={c} lists={data} onClose={() => setDrawer(null)} onSaved={onChanged} />}
      {drawer === "retire" && <RetireControl c={c} onClose={() => setDrawer(null)} onDone={onChanged} />}
    </>
  );
}

function ControlEditor({ control, lists, onClose, onSaved }: { control?: SodControl; lists: SodControlList; onClose: () => void; onSaved: (c: SodControl) => void }) {
  const toast = useToast();
  const { data: people } = useApi<IdentityRow[]>("/identities?status=active");
  const [name, setName] = useState(control?.name ?? "");
  const [description, setDescription] = useState(control?.description ?? "");
  const [owner, setOwner] = useState<number | null>(control?.owner?.id ?? null);
  const [type, setType] = useState<SodControlSpec["type"]>(control?.type ?? "detective");
  const [frequency, setFrequency] = useState<SodControlSpec["frequency"]>(control?.frequency ?? "monthly");
  const [evidence, setEvidence] = useState(control?.evidence_requirement ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const ready = name.trim() !== "" && owner !== null && !busy;
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setErr(null);
    try {
      const spec = { name: name.trim(), description, owner_id: owner, type, frequency, evidence_requirement: evidence };
      const saved = control ? await sodControls.update(control.id, control.version, spec) : await sodControls.create(spec);
      toast(`Control “${saved.name}” saved`);
      onSaved(saved);
      onClose();
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={control ? `Edit ${control.name}` : "New mitigating control"} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="sod-ctl-form" variant="primary" disabled={!ready}>{control ? "Save" : "Create control"}</Button></>}>
      <form id="sod-ctl-form" className="stack" onSubmit={save}>
        <label className="field">Name<input className="input" data-autofocus value={name} onChange={(e) => setName(e.target.value)} maxLength={120} placeholder="e.g. Monthly payments review" /></label>
        <label className="field">Description<textarea className="input" value={description} onChange={(e) => setDescription(e.target.value)} /></label>
        <label className="field">Owner
          <select className="input" value={owner ?? ""} onChange={(e) => setOwner(e.target.value ? Number(e.target.value) : null)}>
            <option value="">Select…</option>
            {(people ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </label>
        <div className="grid g2">
          <label className="field">Type<select className="input" value={type} onChange={(e) => setType(e.target.value as SodControlSpec["type"])}>{lists.types.map((t) => <option key={t} value={t}>{t}</option>)}</select></label>
          <label className="field">Frequency<select className="input" value={frequency} onChange={(e) => setFrequency(e.target.value as SodControlSpec["frequency"])}>{lists.frequencies.map((f) => <option key={f} value={f}>{f}</option>)}</select></label>
        </div>
        <label className="field">Evidence requirement<textarea className="input" value={evidence} onChange={(e) => setEvidence(e.target.value)} maxLength={2000} placeholder="What the owner must show, and how often" /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

function RetireControl({ c, onClose, onDone }: { c: SodControl; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [why, setWhy] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const go = async () => {
    setBusy(true);
    try {
      await sodControls.retire(c.id, why.trim());
      toast("Control retired");
      onDone();
      onClose();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={`Retire ${c.name}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="danger" disabled={busy || !why.trim() || c.active_mitigations > 0} onClick={go}>Retire control</Button></>}>
      <div className="stack">
        {c.active_mitigations > 0 ? <Callout tone="warn">It covers {c.active_mitigations} violation{c.active_mitigations === 1 ? "" : "s"} now. Wait for them to end or end them early first.</Callout> : <p className="small muted">A retired control cannot be used for new mitigations. Its history stays.</p>}
        <label className="field">Reason<input className="input" data-autofocus value={why} onChange={(e) => setWhy(e.target.value)} maxLength={500} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}
