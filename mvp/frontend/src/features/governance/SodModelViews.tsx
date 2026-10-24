/**
 * SoD functions, risks and rulesets (issue #298), the three tabs of Protection → Policies & SoD.
 * A function is a reusable set of entitlements; a risk is a prioritised conflict between two or
 * more functions; a ruleset groups risks, can be switched off, keeps its versions and round-trips
 * as a YAML file. Writes need a policy admin and a fresh sign-in (the client handles the prompt).
 */
import { FormEvent, useEffect, useState } from "react";
import { Archive, Download, FileUp, History, ListChecks, Pencil, Plus, Power, Trash2 } from "lucide-react";
import {
  IdentityRow, SodFunction, SodFunctionList, SodImportResult, SodPriority, SodRemediation, SodRisk, SodRiskList, SodRuleset, SodRulesetList, SodSelector,
  fmtDate, relTime, sod, sodPaths, useApi,
} from "../../api";
import { Badge, Button, Callout, CommandBar, DataTable, Drawer, EmptyState, Loading, SidePanel, Sev, Tabs, useSelected, useToast } from "../../components";
import { ATTRIBUTES, PRIORITIES, REMEDIATION, cleanSelector, describeOptions, describeSelector, describeSubjects, escalationLabel, optionsError, optionsToSend, riskError, selectorError, sourceLabel } from "./sodModel";

const I = 16;
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

type PanelTab = "overview" | "history";

function History_({ versions }: { versions?: { version: number; actor: string; changed_at: string; note: string | null }[] }) {
  if (!versions) return <Loading kind="block" />;
  return (
    <ol className="timeline">
      {versions.map((v) => (
        <li key={v.version}>
          <b>Version {v.version}</b> by {v.actor} <span className="faint" title={fmtDate(v.changed_at)}>{relTime(v.changed_at)}</span>
          {v.note && <div className="small">{v.note}</div>}
        </li>
      ))}
    </ol>
  );
}

/** One form's busy/error state and its submit wrapper. */
function useSubmit(onDone: () => void) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return { busy, err, run };
}

function RetireDrawer({ what, name, blocked, onRetire, onClose }: { what: string; name: string; blocked?: string; onRetire: (reason: string) => Promise<unknown>; onClose: () => void }) {
  const [why, setWhy] = useState("");
  const { busy, err, run } = useSubmit(onClose);
  return (
    <Drawer title={`Retire ${name}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="danger" disabled={busy || !!blocked || !why.trim()} onClick={() => run(() => onRetire(why.trim()))}>Retire {what}</Button></>}>
      <div className="stack">
        {blocked ? <Callout tone="warn">{blocked}</Callout> : <p className="small muted">A retired {what} cannot be edited or used. Its history stays.</p>}
        <label className="field">Reason<input className="input" data-autofocus value={why} onChange={(e) => setWhy(e.target.value)} maxLength={500} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}

function usePeople() {
  const { data } = useApi<IdentityRow[]>("/identities?status=active");
  return (data ?? []).slice().sort((a, b) => a.name.localeCompare(b.name));
}

function OwnerSelect({ value, onChange }: { value: number | null; onChange: (v: number | null) => void }) {
  const people = usePeople();
  return (
    <label className="field">Owner
      <select className="input" value={value ?? ""} onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}>
        <option value="">No owner</option>
        {people.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
      </select>
    </label>
  );
}

// ------------------------------------------------------------------ functions

export function SodFunctionsView() {
  const { data, error, reload } = useApi<SodFunctionList>(sodPaths.functions);
  const [selected, setSelected] = useSelected();
  const [creating, setCreating] = useState(false);
  const rows = data?.functions ?? null;
  const open = rows?.find((f) => f.id === selected);
  return (
    <>
      <DataTable
        id="sod-functions"
        rows={rows}
        error={error}
        rowKey={(f) => f.id}
        columns={[
          { id: "name", header: "Function", sort: (f) => f.name, cell: (f) => <div><span className="name-link">{f.name}</span><div className="xs faint truncate" style={{ maxWidth: 520 }}>{f.selectors.map(describeSelector).join(" · ")}</div></div> },
          { id: "owner", header: "Owner", sort: (f) => f.owner?.name ?? "", cell: (f) => f.owner?.name ?? <span className="faint">None</span>, hideNarrow: true },
          { id: "risks", header: "Risks", num: true, sort: (f) => f.used_by.length, cell: (f) => f.used_by.length },
          { id: "status", header: "Status", sort: (f) => f.status, cell: (f) => (f.status === "retired" ? <Badge>Retired</Badge> : <span className="small faint">Active</span>) },
          { id: "updated", header: "Updated", sort: (f) => f.updated_at, cell: (f) => <span className="small nowrap" title={fmtDate(f.updated_at)}>{relTime(f.updated_at)}</span>, hideNarrow: true },
        ]}
        searchText={(f) => `${f.name} ${f.description} ${f.selectors.map(describeSelector).join(" ")}`}
        searchPlaceholder="Search functions or their entitlements…"
        filters={[{ id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "retired", label: "Retired" }], get: (f) => f.status }]}
        commands={[data?.can_manage && { label: "New function", icon: <Plus size={I} />, onClick: () => setCreating(true) }]}
        onRefresh={reload}
        rowLabel={(f) => f.name}
        onRowClick={(f) => setSelected(f.id)}
        activeKey={selected}
        empty={<EmptyState title="No SoD functions yet">A function is a named set of entitlements, such as “Create supplier payments”. Risks say which functions must not be held together.</EmptyState>}
      />
      {open && data && <FunctionPanel f={open} canManage={data.can_manage} onClose={() => setSelected(null)} onChanged={reload} />}
      {creating && <FunctionEditor onClose={() => setCreating(false)} onSaved={(f) => { reload(); setSelected(f.id); }} />}
    </>
  );
}

function FunctionPanel({ f: summary, canManage, onClose, onChanged }: { f: SodFunction; canManage: boolean; onClose: () => void; onChanged: () => void }) {
  const { data: detail, reload } = useApi<SodFunction>(sodPaths.function(summary.id));
  const f = detail ?? summary;
  const [tab, setTab] = useState<PanelTab>("overview");
  const [drawer, setDrawer] = useState<null | "edit" | "retire">(null);
  useEffect(() => setTab("overview"), [summary.id]);
  const done = () => { reload(); onChanged(); };
  const manage = canManage && f.status === "active";
  return (
    <>
      <SidePanel title={f.name} sub={f.status === "retired" ? <Badge>Retired</Badge> : <Badge tone="info">Version {f.version}</Badge>} onClose={onClose}
        commands={<CommandBar label={`Actions for ${f.name}`} items={[
          manage && { label: "Edit", icon: <Pencil size={I} />, onClick: () => setDrawer("edit") },
          manage && { label: "Retire", icon: <Archive size={I} />, danger: true, onClick: () => setDrawer("retire") },
        ]} />}
        tabs={<Tabs label="Function details" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "history", label: <><History size={13} aria-hidden /> History</> }]} />}>
        {tab === "overview" ? (
          <div className="stack">
            <p className="muted">{f.description || <span className="faint">No description</span>}</p>
            <div>
              <div className="small muted">Entitlements it covers</div>
              <ul className="stack-sm">{f.selectors.map((s, i) => <li key={i} className="sys small">{describeSelector(s)}</li>)}</ul>
            </div>
            <dl className="kv">
              <dt>Owner</dt><dd>{f.owner?.name ?? <span className="faint">None</span>}</dd>
              <dt>Used by risks</dt><dd>{f.used_by.length ? f.used_by.map((r) => <Badge key={r.id} tone="outline">{r.name}</Badge>) : <span className="faint">None</span>}</dd>
              <dt>Updated</dt><dd title={fmtDate(f.updated_at)}>{relTime(f.updated_at)}{f.updated_by && ` by ${f.updated_by.display_name}`}</dd>
            </dl>
          </div>
        ) : <History_ versions={detail?.versions} />}
      </SidePanel>
      {drawer === "edit" && <FunctionEditor fn={f} onClose={() => setDrawer(null)} onSaved={done} />}
      {drawer === "retire" && <RetireDrawer what="function" name={f.name} blocked={f.used_by.length ? `It is used by ${plural(f.used_by.length, "risk")}. Remove it from them first.` : undefined}
        onRetire={async (r) => { await sod.retireFunction(f.id, r); done(); }} onClose={() => setDrawer(null)} />}
    </>
  );
}

function SelectorRows({ value, onChange }: { value: SodSelector[]; onChange: (v: SodSelector[]) => void }) {
  const set = (i: number, patch: Partial<SodSelector>) => onChange(value.map((s, j) => (j === i ? { ...s, ...patch } : s)));
  return (
    <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
      <legend className="small muted">Entitlements (any one of these is the function)</legend>
      {value.map((s, i) => (
        <div key={i} className="stack-sm card">
          <div className="grid g2">
            <label className="field">System (blank: any)<input className="input" value={s.system ?? ""} onChange={(e) => set(i, { system: e.target.value })} placeholder="e.g. workday" /></label>
            <label className="field">Action name pattern<input className="input" value={s.name_pattern ?? ""} onChange={(e) => set(i, { name_pattern: e.target.value, entitlement_id: undefined })} placeholder="payments:approve or payments:*" aria-describedby="pattern-help" /></label>
          </div>
          <div className="grid g2">
            <label className="field">Narrow by (optional)
              <select className="input" value={s.attribute ?? ""} onChange={(e) => set(i, { attribute: (e.target.value || undefined) as SodSelector["attribute"], value: e.target.value ? s.value : undefined })}>
                <option value="">Nothing</option>
                {ATTRIBUTES.map((a) => <option key={a.value} value={a.value}>{a.label}</option>)}
              </select>
            </label>
            <label className="field">Value<input className="input" disabled={!s.attribute} value={s.value ?? ""} onChange={(e) => set(i, { value: e.target.value })} placeholder={ATTRIBUTES.find((a) => a.value === s.attribute)?.hint ?? ""} /></label>
          </div>
          {s.entitlement_id !== undefined && <p className="xs faint">Selects entitlement #{s.entitlement_id} in {s.system}.</p>}
          {selectorError(cleanSelector(s)) && <p className="xs" role="alert">{selectorError(cleanSelector(s))}</p>}
          {value.length > 1 && <div><Button size="sm" variant="ghost" icon={<Trash2 size={14} />} onClick={() => onChange(value.filter((_, j) => j !== i))}>Remove</Button></div>}
        </div>
      ))}
      <p id="pattern-help" className="xs faint">In a pattern, <code>*</code> matches any run of characters. The fine-grained case (an auth object, field and value) is a pattern narrowed by an attribute of the resource.</p>
      <div><Button size="sm" icon={<Plus size={14} />} onClick={() => onChange([...value, {}])}>Add entitlement</Button></div>
    </fieldset>
  );
}

function FunctionEditor({ fn, onClose, onSaved }: { fn?: SodFunction; onClose: () => void; onSaved: (f: SodFunction) => void }) {
  const toast = useToast();
  const [name, setName] = useState(fn?.name ?? "");
  const [description, setDescription] = useState(fn?.description ?? "");
  const [owner, setOwner] = useState<number | null>(fn?.owner?.id ?? null);
  const [sels, setSels] = useState<SodSelector[]>(fn?.selectors.length ? fn.selectors : [{}]);
  const [note, setNote] = useState("");
  const { busy, err, run } = useSubmit(onClose);
  const cleaned = sels.map(cleanSelector);
  const ready = name.trim() !== "" && cleaned.every((s) => !selectorError(s)) && !busy;
  const save = (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    void run(async () => {
      const spec = { name: name.trim(), description, owner_id: owner, selectors: cleaned, note };
      const saved = fn ? await sod.updateFunction(fn.id, fn.version, spec) : await sod.createFunction(spec);
      toast(`Function “${saved.name}” saved as version ${saved.version}`);
      onSaved(saved);
    });
  };
  return (
    <Drawer title={fn ? `Edit ${fn.name}` : "New SoD function"} onClose={onClose} wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="sod-fn-form" variant="primary" disabled={!ready}>{fn ? "Save new version" : "Create function"}</Button></>}>
      <form id="sod-fn-form" className="stack" onSubmit={save}>
        <label className="field">Name<input className="input" data-autofocus value={name} onChange={(e) => setName(e.target.value)} maxLength={120} placeholder="e.g. Create supplier payments" /></label>
        <label className="field">Description<textarea className="input" value={description} onChange={(e) => setDescription(e.target.value)} /></label>
        <OwnerSelect value={owner} onChange={setOwner} />
        <SelectorRows value={sels} onChange={setSels} />
        <label className="field">Why this change (kept with the version)<input className="input" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

// ------------------------------------------------------------------ risks

export function SodRisksView() {
  const { data, error, reload } = useApi<SodRiskList>(sodPaths.risks);
  const [selected, setSelected] = useSelected();
  const [creating, setCreating] = useState(false);
  const rows = data?.risks ?? null;
  const open = rows?.find((r) => r.id === selected);
  return (
    <>
      <DataTable
        id="sod-risks"
        rows={rows}
        error={error}
        rowKey={(r) => r.id}
        columns={[
          { id: "name", header: "Risk", sort: (r) => r.name, cell: (r) => <div><span className="name-link">{r.name}</span><div className="xs faint truncate" style={{ maxWidth: 520 }}>{r.functions.map((f) => f.name).join("  ⇄  ")}</div></div> },
          { id: "priority", header: "Priority", sort: (r) => PRIORITIES.indexOf(r.priority) * -1, csv: (r) => r.priority, cell: (r) => <Sev s={r.priority} /> },
          { id: "process", header: "Business process", sort: (r) => r.business_process, cell: (r) => r.business_process || <span className="faint">-</span>, hideNarrow: true },
          { id: "ruleset", header: "Ruleset", sort: (r) => r.ruleset.name, cell: (r) => r.ruleset.name, hideNarrow: true },
          { id: "violations", header: "Violations", num: true, sort: (r) => r.violations ?? 0, cell: (r) => r.violations ?? 0 },
          { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => (r.status === "retired" ? <Badge>Retired</Badge> : <span className="small faint">Active</span>) },
        ]}
        initialSort={["priority", 1]}
        searchText={(r) => `${r.name} ${r.description} ${r.business_process} ${r.functions.map((f) => f.name).join(" ")}`}
        searchPlaceholder="Search risks…"
        filters={[
          { id: "priority", label: "Priority", options: PRIORITIES.map((p) => ({ value: p, label: p[0].toUpperCase() + p.slice(1) })), get: (r) => r.priority },
          { id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "retired", label: "Retired" }], get: (r) => r.status },
        ]}
        commands={[data?.can_manage && { label: "New risk", icon: <Plus size={I} />, onClick: () => setCreating(true) }]}
        onRefresh={reload}
        rowLabel={(r) => r.name}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        empty={<EmptyState title="No SoD risks yet">A risk names two or more functions nobody should hold together, with a priority and a business process.</EmptyState>}
      />
      {open && data && <RiskPanel r={open} canManage={data.can_manage} onClose={() => setSelected(null)} onChanged={reload} />}
      {creating && <RiskEditor onClose={() => setCreating(false)} onSaved={(r) => { reload(); setSelected(r.id); }} />}
    </>
  );
}

function RiskPanel({ r: summary, canManage, onClose, onChanged }: { r: SodRisk; canManage: boolean; onClose: () => void; onChanged: () => void }) {
  const { data: detail, reload } = useApi<SodRisk>(sodPaths.risk(summary.id));
  const r = detail ?? summary;
  const [tab, setTab] = useState<PanelTab>("overview");
  const [drawer, setDrawer] = useState<null | "edit" | "retire">(null);
  useEffect(() => setTab("overview"), [summary.id]);
  const done = () => { reload(); onChanged(); };
  const manage = canManage && r.status === "active";
  return (
    <>
      <SidePanel title={r.name} sub={<><Sev s={r.priority} /> {r.status === "retired" ? <Badge>Retired</Badge> : <Badge tone="info">Version {r.version}</Badge>}</>} onClose={onClose}
        commands={<CommandBar label={`Actions for ${r.name}`} items={[
          manage && { label: "Edit", icon: <Pencil size={I} />, onClick: () => setDrawer("edit") },
          manage && { label: "Retire", icon: <Archive size={I} />, danger: true, onClick: () => setDrawer("retire") },
        ]} />}
        tabs={<Tabs label="Risk details" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "history", label: <><History size={13} aria-hidden /> History</> }]} />}>
        {tab === "overview" ? (
          <div className="stack">
            <p className="muted">{r.description || <span className="faint">No description</span>}</p>
            <dl className="kv">
              <dt>Conflicting functions</dt><dd>{r.functions.map((f) => <Badge key={f.id} tone="outline">{f.name}</Badge>)}</dd>
              <dt>Business process</dt><dd>{r.business_process || <span className="faint">None</span>}</dd>
              <dt>Ruleset</dt><dd>{r.ruleset.name}</dd>
              <dt>Owner</dt><dd>{r.owner?.name ?? <span className="faint">None</span>}</dd>
              <dt>Violation options</dt><dd>{describeOptions(r.remediation)} <span className="xs faint">({sourceLabel(r.remediation_source)})</span></dd>
              <dt>Escalates to</dt><dd>{escalationLabel(r.escalate_to)}</dd>
              <dt>Checked for</dt><dd>{describeSubjects(r.subjects)}</dd>
              <dt>Violations</dt><dd>{r.violations ?? 0}</dd>
              <dt>Updated</dt><dd title={fmtDate(r.updated_at)}>{relTime(r.updated_at)}{r.updated_by && ` by ${r.updated_by.display_name}`}</dd>
            </dl>
            <p className="xs faint">A violation is one identity effectively holding at least one entitlement from each of two of the functions, through any path: roles, groups or direct grants.</p>
          </div>
        ) : <History_ versions={detail?.versions} />}
      </SidePanel>
      {drawer === "edit" && <RiskEditor risk={r} onClose={() => setDrawer(null)} onSaved={done} />}
      {drawer === "retire" && <RetireDrawer what="risk" name={r.name} onRetire={async (why) => { await sod.retireRisk(r.id, why); done(); }} onClose={() => setDrawer(null)} />}
    </>
  );
}

function RiskEditor({ risk, rulesetId, onClose, onSaved }: { risk?: SodRisk; rulesetId?: string; onClose: () => void; onSaved: (r: SodRisk) => void }) {
  const toast = useToast();
  const { data: fns } = useApi<SodFunctionList>(sodPaths.functions);
  const { data: sets } = useApi<SodRulesetList>(sodPaths.rulesets);
  const [name, setName] = useState(risk?.name ?? "");
  const [description, setDescription] = useState(risk?.description ?? "");
  const [priority, setPriority] = useState<SodPriority>(risk?.priority ?? "high");
  const [process, setProcess] = useState(risk?.business_process ?? "");
  const [owner, setOwner] = useState<number | null>(risk?.owner?.id ?? null);
  const [ruleset, setRuleset] = useState(risk?.ruleset.id ?? rulesetId ?? "");
  const [fnIds, setFnIds] = useState<string[]>(risk?.functions.map((f) => f.id) ?? []);
  const [types, setTypes] = useState<string[]>(risk?.subjects.identity_types ?? []);
  const [note, setNote] = useState("");
  // the options a violation of this risk offers: its own list, or (not custom) its ruleset's
  const [customOpts, setCustomOpts] = useState(risk?.remediation_source === "risk");
  const [opts, setOpts] = useState<SodRemediation[]>(risk?.remediation ?? REMEDIATION.map((r) => r.id));
  const { busy, err, run } = useSubmit(onClose);
  const problem = riskError({ name, ruleset_id: ruleset, function_ids: fnIds }) ?? optionsError(customOpts, opts);
  const toggle = (id: string) => setFnIds((xs) => (xs.includes(id) ? xs.filter((x) => x !== id) : [...xs, id]));
  const save = (e: FormEvent) => {
    e.preventDefault();
    if (problem || busy) return;
    void run(async () => {
      const subjects = { ...(risk?.subjects ?? {}), identity_types: types.length ? (types as never) : undefined };
      const spec = { name: name.trim(), description, priority, business_process: process, owner_id: owner, ruleset_id: ruleset, function_ids: fnIds, subjects, remediation: optionsToSend(customOpts, opts), note };
      const saved = risk ? await sod.updateRisk(risk.id, risk.version, spec) : await sod.createRisk(spec);
      toast(`Risk “${saved.name}” saved as version ${saved.version}`);
      onSaved(saved);
    });
  };
  const active = (fns?.functions ?? []).filter((f) => f.status === "active");
  return (
    <Drawer title={risk ? `Edit ${risk.name}` : "New SoD risk"} onClose={onClose} wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="sod-risk-form" variant="primary" disabled={!!problem || busy}>{risk ? "Save new version" : "Create risk"}</Button></>}>
      <form id="sod-risk-form" className="stack" onSubmit={save}>
        <label className="field">Name<input className="input" data-autofocus value={name} onChange={(e) => setName(e.target.value)} maxLength={120} placeholder="e.g. Create and approve a supplier payment" /></label>
        <label className="field">Description<textarea className="input" value={description} onChange={(e) => setDescription(e.target.value)} /></label>
        <div className="grid g2">
          <label className="field">Priority
            <select className="input" value={priority} onChange={(e) => setPriority(e.target.value as SodPriority)}>{PRIORITIES.map((p) => <option key={p} value={p}>{p[0].toUpperCase() + p.slice(1)}</option>)}</select>
          </label>
          <label className="field">Business process<input className="input" value={process} onChange={(e) => setProcess(e.target.value)} maxLength={120} placeholder="e.g. Procure to pay" /></label>
        </div>
        <div className="grid g2">
          <label className="field">Ruleset
            <select className="input" value={ruleset} onChange={(e) => setRuleset(e.target.value)}>
              <option value="">Select…</option>
              {(sets?.rulesets ?? []).filter((s) => s.status === "active").map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </label>
          <OwnerSelect value={owner} onChange={setOwner} />
        </div>
        <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="small muted">Conflicting functions (at least two; holding one of each is a violation)</legend>
          {!fns ? <Loading kind="block" /> : active.length === 0 ? <p className="small muted">Create functions first.</p> : active.map((f) => (
            <label key={f.id} className="row small" style={{ flexWrap: "nowrap" }}>
              <input type="checkbox" checked={fnIds.includes(f.id)} onChange={() => toggle(f.id)} />
              <span><b>{f.name}</b> <span className="faint">{f.selectors.map(describeSelector).join(" · ")}</span></span>
            </label>
          ))}
        </fieldset>
        <fieldset className="row" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="small muted">Check only these identity types (none selected: all)</legend>
          {(["human", "service", "ai_agent"] as const).map((t) => (
            <label key={t} className="row tight small"><input type="checkbox" checked={types.includes(t)} onChange={() => setTypes((xs) => (xs.includes(t) ? xs.filter((x) => x !== t) : [...xs, t]))} />{t}</label>
          ))}
        </fieldset>
        <OptionsFields custom={customOpts} onCustom={setCustomOpts} chosen={opts} onChosen={setOpts} inheritLabel="Use the ruleset's options (every option if it sets none)" legend="What a violation of this risk offers" />
        <label className="field">Why this change (kept with the version)<input className="input" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} /></label>
        {problem && name.trim() !== "" && <p className="small" role="status">{problem}</p>}
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

/** Pick the remediation options a violation offers, or inherit them. The server refuses any option that is not offered. */
function OptionsFields({ custom, onCustom, chosen, onChosen, inheritLabel, legend }: {
  custom: boolean; onCustom: (v: boolean) => void; chosen: SodRemediation[]; onChosen: (v: SodRemediation[]) => void; inheritLabel: string; legend: string;
}) {
  const toggle = (id: SodRemediation) => onChosen(chosen.includes(id) ? chosen.filter((x) => x !== id) : [...chosen, id]);
  return (
    <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
      <legend className="small muted">{legend}</legend>
      <label className="row small"><input type="radio" name="sod-opts" checked={!custom} onChange={() => onCustom(false)} /> {inheritLabel}</label>
      <label className="row small"><input type="radio" name="sod-opts" checked={custom} onChange={() => onCustom(true)} /> Choose the options</label>
      {custom && (
        <div className="stack-sm" style={{ paddingLeft: 22 }}>
          {REMEDIATION.map((r) => (
            <label key={r.id} className="row small" style={{ alignItems: "flex-start", flexWrap: "nowrap" }}>
              <input type="checkbox" checked={chosen.includes(r.id)} onChange={() => toggle(r.id)} />
              <span><b>{r.label}</b><span className="faint"> · {r.hint}</span></span>
            </label>
          ))}
        </div>
      )}
    </fieldset>
  );
}

/** What a ruleset's risks offer on a violation, and who an escalation goes to. */
function RemediationDrawer({ ruleset, onClose, onSaved }: { ruleset: SodRuleset; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const people = usePeople();
  const [custom, setCustom] = useState(ruleset.remediation.length < REMEDIATION.length);
  const [chosen, setChosen] = useState<SodRemediation[]>(ruleset.remediation);
  const [approver, setApprover] = useState<number | null>(ruleset.escalate_to?.id ?? null);
  const { busy, err, run } = useSubmit(onClose);
  const problem = optionsError(custom, chosen);
  const save = (e: FormEvent) => {
    e.preventDefault();
    if (problem || busy) return;
    void run(async () => {
      await sod.setRulesetRemediation(ruleset.id, optionsToSend(custom, chosen), approver);
      toast(`Violation options of “${ruleset.name}” saved`);
      onSaved();
    });
  };
  return (
    <Drawer title={`Violation options of ${ruleset.name}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="sod-rem-form" variant="primary" disabled={!!problem || busy}>Save options</Button></>}>
      <form id="sod-rem-form" className="stack" onSubmit={save}>
        <p className="small muted">These apply to every risk of the ruleset that does not set options of its own. The server refuses an option a risk does not offer.</p>
        <OptionsFields custom={custom} onCustom={setCustom} chosen={chosen} onChosen={setChosen} inheritLabel="Offer every option" legend="What a violation offers" />
        <label className="field">Escalation approver
          <select className="input" value={approver ?? ""} onChange={(e) => setApprover(e.target.value ? Number(e.target.value) : null)}>
            <option value="">The owner of the risk</option>
            {people.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <span className="hint">An escalation creates an inbox item for this person (or, without one, the risk owner).</span>
        </label>
        {problem && <p className="small" role="status">{problem}</p>}
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

// ------------------------------------------------------------------ rulesets

export function SodRulesetsView() {
  const { data, error, reload } = useApi<SodRulesetList>(sodPaths.rulesets);
  const [selected, setSelected] = useSelected();
  const [drawer, setDrawer] = useState<null | "new" | "import">(null);
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const rows = data?.rulesets ?? null;
  const open = rows?.find((r) => r.id === selected);
  const importLegacy = async () => {
    setBusy(true);
    setErr(null);
    try {
      const res = await sod.importLegacy();
      toast(`Imported ${res.created.length} object${res.created.length === 1 ? "" : "s"} from the policy files`);
      reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      {data?.legacy && (
        <Callout tone="info">
          Separation of duties is currently checked from the <code>separation_of_duties</code> policy files. Import them once to manage them here as functions, risks and a ruleset; findings stay the same.
          {data.can_manage && <div className="mt-sm"><Button size="sm" onClick={importLegacy} disabled={busy}>Import the policy files</Button></div>}
        </Callout>
      )}
      {err && <Callout tone="bad">{err}</Callout>}
      <DataTable
        id="sod-rulesets"
        rows={rows}
        error={error}
        rowKey={(r) => r.id}
        columns={[
          { id: "name", header: "Ruleset", sort: (r) => r.name, cell: (r) => <div><span className="name-link">{r.name}</span><div className="xs faint truncate" style={{ maxWidth: 520 }}>{r.description}</div></div> },
          { id: "enabled", header: "State", sort: (r) => (r.enabled ? 1 : 0), csv: (r) => (r.enabled ? "enabled" : "disabled"), cell: (r) => (r.status === "retired" ? <Badge>Retired</Badge> : r.enabled ? <Badge tone="ok">Enabled</Badge> : <Badge>Disabled</Badge>) },
          { id: "risks", header: "Risks", num: true, sort: (r) => r.risks, cell: (r) => r.risks },
          { id: "violations", header: "Violations", num: true, sort: (r) => r.violations ?? 0, cell: (r) => r.violations ?? 0 },
          { id: "version", header: "Version", num: true, sort: (r) => r.version, cell: (r) => `v${r.version}`, hideNarrow: true },
        ]}
        searchText={(r) => `${r.name} ${r.description}`}
        searchPlaceholder="Search rulesets…"
        filters={[{ id: "state", label: "State", options: [{ value: "enabled", label: "Enabled" }, { value: "disabled", label: "Disabled" }, { value: "retired", label: "Retired" }], get: (r) => (r.status === "retired" ? "retired" : r.enabled ? "enabled" : "disabled") }]}
        commands={[
          data?.can_manage && { label: "New ruleset", icon: <Plus size={I} />, onClick: () => setDrawer("new") },
          data?.can_manage && { label: "Import YAML", icon: <FileUp size={I} />, onClick: () => setDrawer("import") },
        ]}
        onRefresh={reload}
        rowLabel={(r) => r.name}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        empty={<EmptyState title="No rulesets yet">A ruleset groups risks and can be switched on or off for the tenant. Create one, or import a YAML file.</EmptyState>}
      />
      {open && data && <RulesetPanel r={open} canManage={data.can_manage} onClose={() => setSelected(null)} onChanged={reload} />}
      {drawer === "new" && <RulesetEditor onClose={() => setDrawer(null)} onSaved={(r) => { reload(); setSelected(r.id); }} />}
      {drawer === "import" && <ImportDrawer onClose={() => setDrawer(null)} onDone={reload} />}
    </>
  );
}

function RulesetPanel({ r: summary, canManage, onClose, onChanged }: { r: SodRuleset; canManage: boolean; onClose: () => void; onChanged: () => void }) {
  const { data: detail, reload } = useApi<SodRuleset>(sodPaths.ruleset(summary.id));
  const { data: risks } = useApi<SodRiskList>(sodPaths.risks);
  const r = detail ?? summary;
  const toast = useToast();
  const [tab, setTab] = useState<"overview" | "yaml" | "history">("overview");
  const [drawer, setDrawer] = useState<null | "edit" | "retire" | "risk" | "options">(null);
  const [yaml, setYaml] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { setTab("overview"); setYaml(null); }, [summary.id]);
  useEffect(() => {
    if (tab !== "yaml") return;
    setYaml(null);
    sod.exportRuleset(summary.id).then((x) => setYaml(x.yaml)).catch((e) => setErr((e as Error).message));
  }, [tab, summary.id, r.version]);
  const done = () => { reload(); onChanged(); };
  const manage = canManage && r.status === "active";
  const toggle = async () => {
    setErr(null);
    try {
      await sod.updateRuleset(r.id, r.version, { name: r.name, description: r.description, enabled: !r.enabled, note: r.enabled ? "disabled" : "enabled" });
      toast(r.enabled ? "Ruleset disabled" : "Ruleset enabled");
      done();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const download = () => {
    if (!yaml) return;
    const url = URL.createObjectURL(new Blob([yaml], { type: "application/yaml" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${r.key}.sod.yaml`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const mine = (risks?.risks ?? []).filter((x) => x.ruleset.id === r.id && x.status === "active");
  return (
    <>
      <SidePanel title={r.name} sub={r.status === "retired" ? <Badge>Retired</Badge> : <>{r.enabled ? <Badge tone="ok">Enabled</Badge> : <Badge>Disabled</Badge>} <Badge tone="info">Version {r.version}</Badge></>} onClose={onClose}
        commands={<CommandBar label={`Actions for ${r.name}`} items={[
          manage && { label: r.enabled ? "Disable" : "Enable", icon: <Power size={I} />, onClick: toggle },
          manage && { label: "Edit", icon: <Pencil size={I} />, onClick: () => setDrawer("edit") },
          manage && { label: "Add risk", icon: <Plus size={I} />, onClick: () => setDrawer("risk") },
          manage && { label: "Violation options", icon: <ListChecks size={I} />, onClick: () => setDrawer("options") },
          manage && { label: "Retire", icon: <Archive size={I} />, danger: true, onClick: () => setDrawer("retire") },
        ]} />}
        tabs={<Tabs label="Ruleset details" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Risks" }, { id: "yaml", label: "YAML" }, { id: "history", label: <><History size={13} aria-hidden /> History</> }]} />}>
        {err && <Callout tone="bad">{err}</Callout>}
        {tab === "overview" && (
          <div className="stack">
            <p className="muted">{r.description || <span className="faint">No description</span>}</p>
            {!r.enabled && r.status === "active" && <Callout tone="warn">Disabled: none of its risks is checked and none of its violations is reported.</Callout>}
            <dl className="kv">
              <dt>Violation options</dt><dd>{describeOptions(r.remediation)}</dd>
              <dt>Escalates to</dt><dd>{r.escalate_to?.name ?? <span className="faint">The owner of each risk</span>}</dd>
            </dl>
            {mine.length === 0 ? <p className="small muted">No active risks.</p> : (
              <ul className="stack-sm">{mine.map((x) => <li key={x.id} className="row tight"><Sev s={x.priority} /><span>{x.name}</span><span className="xs faint">{plural(x.violations ?? 0, "violation")}</span></li>)}</ul>
            )}
          </div>
        )}
        {tab === "yaml" && (
          <div className="stack">
            <p className="small muted">The ruleset as a file you can keep in git and import elsewhere. Importing the same file changes nothing.</p>
            {yaml === null ? <Loading kind="block" /> : <pre className="yaml" tabIndex={0} aria-label="Ruleset YAML">{yaml}</pre>}
            <div><Button size="sm" icon={<Download size={14} />} onClick={download} disabled={!yaml}>Download</Button></div>
          </div>
        )}
        {tab === "history" && <History_ versions={detail?.versions} />}
      </SidePanel>
      {drawer === "edit" && <RulesetEditor ruleset={r} onClose={() => setDrawer(null)} onSaved={done} />}
      {drawer === "risk" && <RiskEditor rulesetId={r.id} onClose={() => setDrawer(null)} onSaved={done} />}
      {drawer === "options" && <RemediationDrawer ruleset={r} onClose={() => setDrawer(null)} onSaved={done} />}
      {drawer === "retire" && <RetireDrawer what="ruleset" name={r.name} blocked={r.risks ? "It still has active risks. Retire or move them first." : undefined}
        onRetire={async (why) => { await sod.retireRuleset(r.id, why); done(); }} onClose={() => setDrawer(null)} />}
    </>
  );
}

function RulesetEditor({ ruleset, onClose, onSaved }: { ruleset?: SodRuleset; onClose: () => void; onSaved: (r: SodRuleset) => void }) {
  const toast = useToast();
  const [name, setName] = useState(ruleset?.name ?? "");
  const [description, setDescription] = useState(ruleset?.description ?? "");
  const [enabled, setEnabled] = useState(ruleset?.enabled ?? true);
  const [note, setNote] = useState("");
  const { busy, err, run } = useSubmit(onClose);
  const save = (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim() || busy) return;
    void run(async () => {
      const spec = { name: name.trim(), description, enabled, note };
      const saved = ruleset ? await sod.updateRuleset(ruleset.id, ruleset.version, spec) : await sod.createRuleset(spec);
      toast(`Ruleset “${saved.name}” saved as version ${saved.version}`);
      onSaved(saved);
    });
  };
  return (
    <Drawer title={ruleset ? `Edit ${ruleset.name}` : "New ruleset"} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="sod-rs-form" variant="primary" disabled={!name.trim() || busy}>{ruleset ? "Save new version" : "Create ruleset"}</Button></>}>
      <form id="sod-rs-form" className="stack" onSubmit={save}>
        <label className="field">Name<input className="input" data-autofocus value={name} onChange={(e) => setName(e.target.value)} maxLength={120} placeholder="e.g. Finance" /></label>
        <label className="field">Description<textarea className="input" value={description} onChange={(e) => setDescription(e.target.value)} /></label>
        <label className="row small"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled (its risks are checked)</label>
        <label className="field">Why this change (kept with the version)<input className="input" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

function ImportDrawer({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [text, setText] = useState("");
  const [prune, setPrune] = useState(false);
  const [plan, setPlan] = useState<SodImportResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setPlan(null), [text, prune]);
  const go = async (dry: boolean) => {
    setBusy(true);
    setErr(null);
    try {
      const res = await sod.importRuleset(text, { prune, dry_run: dry });
      if (dry) setPlan(res);
      else {
        toast(`Imported ruleset ${res.ruleset}`);
        onDone();
        onClose();
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const lines = plan ? ([["Create", plan.created], ["Update", plan.updated], ["Retire", plan.retired], ["Unchanged", plan.unchanged]] as const) : [];
  return (
    <Drawer title="Import a ruleset from YAML" onClose={onClose} wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button onClick={() => go(true)} disabled={busy || !text.trim()}>Preview</Button><Button variant="primary" onClick={() => go(false)} disabled={busy || !plan}>Import</Button></>}>
      <div className="stack">
        <p className="small muted">Functions and risks are matched by key and created or updated; the ruleset gets one new version. Owners are the external ids of identities.</p>
        <label className="field">Ruleset file<textarea className="input mono" rows={16} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} data-autofocus placeholder={"schema: tessera.sod/v1\nruleset:\n  key: finance\n  name: Finance\n  enabled: true\nfunctions: []\nrisks: []"} /></label>
        <label className="row small"><input type="checkbox" checked={prune} onChange={(e) => setPrune(e.target.checked)} /> Retire risks of this ruleset that the file no longer lists</label>
        {err && <Callout tone="bad">{err}</Callout>}
        {plan && (
          <div className="stack-sm" aria-live="polite">
            {lines.map(([label, items]) => items.length > 0 && <div key={label}><b>{label}</b> <span className="small muted">{items.join(", ")}</span></div>)}
            {lines.every(([, items]) => items.length === 0) && <p className="small muted">Nothing to do.</p>}
          </div>
        )}
      </div>
    </Drawer>
  );
}
