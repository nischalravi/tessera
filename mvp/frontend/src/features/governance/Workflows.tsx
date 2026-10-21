import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Plus, Trash2, Workflow as WorkflowIcon, X } from "lucide-react";
import {
  CatalogView, GrpGroup, GrpList, QuestionnaireList, Workflow, WorkflowDetail, WorkflowIssue, WorkflowList, WorkflowScope, WorkflowStep, WorkflowStepType, WorkflowTarget, WorkflowVocabulary,
  fmtDate, questionnairesPath, relTime, useApi, workflows as wfApi, workflowsPath,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Chip, Column, DataTable, EmptyState, GovernanceTabs, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import {
  APPROVER_LABEL, ATTRIBUTE_LABEL, ATTRIBUTE_VALUES, END, LIMITS, NOTIFY_LABEL, OP_LABEL, REQUEST_TYPE_LABEL, STEP_TYPES, appliesTo, blankStep, cleanSteps, describeStep, flowLabel,
  localProblems, moveStep, removeStep, retypeStep, sameSteps, scopeLabel, stepTypeLabel,
} from "./workflowModel";

/**
 * Governance → Workflows (issue #298): configurable, versioned workflows that route approvals.
 * A workflow is an ordered list of steps (approval, questionnaire, notify, wait, condition,
 * provisioning) assigned to catalog items and request types; a request follows the path its
 * conditions select, through the same stages, delegation, escalation and four-eyes rules as any
 * request. Saving an edit makes the next version; requests in flight finish on theirs. Items with
 * no workflow keep their approval policy. Creating, editing, retiring and assigning need
 * workflows.manage and a fresh sign-in, and are audited; the server validates every definition.
 */
export function Workflows() {
  const { can } = useSession();
  const list = useApi<WorkflowList>(workflowsPath);
  const [selected, setSelected] = useSelected();
  const rows = list.data?.workflows ?? null;
  const manage = !!list.data?.can_manage && can("workflows.manage");
  const creating = selected === "new";
  const current = rows?.find((w) => w.id === selected) ?? null;
  const cols: Column<Workflow>[] = [
    { id: "name", header: "Workflow", sort: (w) => w.name, cell: (w) => <span className="name-link">{w.name}</span> },
    { id: "scope", header: "Routes", sort: (w) => w.scope, cell: (w) => <span className="small">{scopeLabel(w.scope)}</span>, hideNarrow: true },
    { id: "status", header: "Status", sort: (w) => w.status, cell: (w) => <Badge tone={w.status === "active" ? "ok" : "outline"}>{w.status === "active" ? "Active" : "Retired"}</Badge> },
    { id: "version", header: "Version", num: true, sort: (w) => w.version, cell: (w) => `v${w.version}`, hideNarrow: true },
    { id: "steps", header: "Steps", num: true, sort: (w) => w.steps.length, cell: (w) => w.steps.length, hideNarrow: true },
    { id: "applies", header: "Applies to", sort: (w) => appliesTo(w.targets), cell: (w) => <span className="small">{appliesTo(w.targets)}</span>, hideNarrow: true },
    { id: "runs", header: "Requests", num: true, sort: (w) => w.runs, cell: (w) => w.runs, hideNarrow: true },
    { id: "updated", header: "Updated", sort: (w) => w.updated_at, cell: (w) => <span className="small faint nowrap" title={fmtDate(w.updated_at)}>{relTime(w.updated_at)}</span>, hideNarrow: true },
  ];
  return (
    <Page
      tabs={<GovernanceTabs />}
      title="Workflows"
      crumbs={[["Access"], ["Access reviews", "/governance/reviews"], ["Workflows"]]}
      sub="Who approves what, in which order, and what happens when nobody answers. A request follows the workflow assigned to its item or request type; with none, the item's approval policy routes it as before."
    >
      <div className="stack">
        {!manage && list.data && <Callout tone="neutral">Workflows are managed by people who hold workflows.manage. You can read them here.</Callout>}
        {list.error && <Callout tone="bad">{list.error.message}</Callout>}
        <DataTable
          id="workflows"
          rows={rows}
          error={list.error}
          rowKey={(w) => w.id}
          columns={cols}
          searchText={(w) => `${w.name} ${w.description} ${appliesTo(w.targets)}`}
          searchPlaceholder="Search workflows…"
          filters={[
            { id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "retired", label: "Retired" }], get: (w) => w.status },
            { id: "scope", label: "Routes", options: [{ value: "access", label: "Access requests" }, { value: "service_account", label: "Service accounts" }], get: (w) => w.scope },
          ]}
          commands={manage ? [{ label: "New workflow", icon: <Plus size={16} />, onClick: () => setSelected("new") }] : []}
          onRefresh={list.reload}
          rowLabel={(w) => w.name}
          onRowClick={(w) => setSelected(w.id)}
          activeKey={current?.id ?? null}
          empty={<EmptyState title="No workflows yet" icon={<WorkflowIcon size={18} />}>Create one, then assign it to a catalog item or a request type. Until then every item keeps its approval policy.</EmptyState>}
        />
      </div>
      {list.data && (creating || current) && (
        <Editor key={creating ? "new" : `${current!.id}-${current!.version}-${current!.status}`} w={creating ? null : current} vocab={list.data} manage={manage}
          onClose={() => setSelected(null)} onSaved={(id) => { list.reload(); if (id) setSelected(id); }} />
      )}
    </Page>
  );
}

type Vocab = WorkflowVocabulary;

function Editor({ w, vocab, manage, onClose, onSaved }: { w: Workflow | null; vocab: Vocab; manage: boolean; onClose: () => void; onSaved: (id?: string) => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const detail = useApi<WorkflowDetail>(w ? `${workflowsPath}/${encodeURIComponent(w.id)}` : null);
  const questionnaires = useApi<QuestionnaireList>(manage ? questionnairesPath : null);
  const groups = useApi<GrpList<GrpGroup>>("/groups/native?limit=500");
  const [scope, setScope] = useState<WorkflowScope>(w?.scope ?? "access");
  const [name, setName] = useState(w?.name ?? "");
  const [description, setDescription] = useState(w?.description ?? "");
  const [steps, setSteps] = useState<WorkflowStep[]>(w?.steps ?? []);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const retired = w?.status === "retired";
  const readOnly = !manage || retired;
  const approvers = vocab.approvers[scope];
  const attributes = vocab.attributes[scope];
  const qNames = useMemo(() => Object.fromEntries((questionnaires.data?.questionnaires ?? []).filter((q) => q.status === "active").map((q) => [q.id, q.title])), [questionnaires.data]);
  const gNames = useMemo(() => Object.fromEntries((groups.data?.items ?? []).map((g) => [g.id, g.display_name || g.name])), [groups.data]);
  const names = { group: (id: string) => gNames[id] ?? id, questionnaire: (id: string) => qNames[id] ?? id };

  const local = localProblems(steps);
  const changed = !w || name.trim() !== w.name || description.trim() !== w.description || !sameSteps(steps, w.steps);
  const textProblem = !name.trim() || name.trim().length > LIMITS.name ? `A name of 1 to ${LIMITS.name} characters is required` : null;

  // the server's checks (cycles, reachability, four eyes), a moment after the last edit
  const [issues, setIssues] = useState<WorkflowIssue[] | null>(null);
  const sig = JSON.stringify([scope, cleanSteps(steps)]);
  useEffect(() => {
    if (readOnly || local.length > 0) {
      setIssues(null);
      return;
    }
    let alive = true;
    const t = setTimeout(() => {
      wfApi.validate(scope, cleanSteps(steps)).then((r) => alive && setIssues(r.issues)).catch(() => alive && setIssues(null));
    }, 400);
    return () => { alive = false; clearTimeout(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig, readOnly]);
  const blocked = local.length > 0 || (issues?.length ?? 0) > 0 || !!textProblem;

  const setStep = (i: number, s: WorkflowStep) => setSteps((xs) => xs.map((x, j) => (j === i ? s : x)));
  const save = async () => {
    if (blocked || busy || readOnly) return;
    setBusy(true);
    setErr(null);
    try {
      const spec = { name: name.trim(), description: description.trim(), steps: cleanSteps(steps) };
      if (w) {
        const r = await wfApi.edit(w.id, w.version, spec);
        toast(`Saved as version ${r.version}`);
        onSaved(w.id);
      } else {
        const r = await wfApi.create(scope, spec);
        toast("Workflow created");
        onSaved(r.id);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const retire = async () => {
    if (!w) return;
    const ok = await confirm({
      title: `Retire ${w.name}?`,
      body: "It stops routing new requests and its assignments are removed: those items and request types go back to their approval policy. Requests already routed by it finish on it.",
      confirmLabel: "Retire", danger: true,
    });
    if (ok == null) return;
    try {
      await wfApi.retire(w.id);
      toast("Workflow retired");
      onSaved(w.id);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };

  return (
    <SidePanel
      title={w ? w.name : "New workflow"}
      sub={w && <span className="small muted">Version {w.version} · {retired ? "retired" : "active"} · {scopeLabel(w.scope)} · {w.runs} request{w.runs === 1 ? "" : "s"} routed</span>}
      onClose={onClose}
      footer={!readOnly && (
        <div className="row tight">
          <Button variant="primary" size="sm" onClick={save} disabled={blocked || !changed || busy}>{w ? "Save as a new version" : "Create"}</Button>
          {w && <Button size="sm" variant="danger" icon={<Trash2 size={14} />} onClick={retire} disabled={busy}>Retire</Button>}
        </div>
      )}
    >
      <div className="stack">
        {retired && <Callout tone="neutral">This workflow is retired. It cannot be edited or assigned.</Callout>}
        <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }} disabled={readOnly}>
          <legend><h3 className="h-sm">Details</h3></legend>
          <label className="field">Name
            <input className="input" value={name} maxLength={LIMITS.name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="field">Description (optional)
            <textarea className="input" rows={2} value={description} maxLength={LIMITS.description} onChange={(e) => setDescription(e.target.value)} />
          </label>
          {!w && (
            <label className="field">Routes
              <select className="input" value={scope} onChange={(e) => { setScope(e.target.value as WorkflowScope); setSteps([]); }} aria-describedby="wf-scope-hint">
                <option value="access">Access requests</option>
                <option value="service_account">Service-account requests</option>
              </select>
              <span className="hint" id="wf-scope-hint">Fixed once created. It decides who can approve and which conditions are offered.</span>
            </label>
          )}
        </fieldset>

        <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }} disabled={readOnly}>
          <legend><h3 className="h-sm">Steps</h3></legend>
          <p className="xs faint">Steps run in this order unless a step jumps elsewhere. Every path needs an approval; provisioning comes after one.</p>
          {steps.length === 0 && <p className="small muted">No steps yet.</p>}
          <ol className="stack-sm" style={{ listStyle: "none", padding: 0, margin: 0 }} aria-label="Steps">
            {steps.map((s, i) => (
              <li key={s.id}>
                <StepEditor s={s} index={i} steps={steps} vocab={vocab} approvers={approvers} attributes={attributes} names={names}
                  questionnaires={questionnaires.data?.questionnaires.filter((q) => q.status === "active") ?? []} groups={groups.data?.items ?? []}
                  problems={[...local.filter((p) => p.step === s.id), ...(issues ?? []).filter((p) => p.step === s.id).map((p) => ({ step: p.step!, message: p.message }))]}
                  onChange={(n) => setStep(i, n)} onMove={(by) => setSteps(moveStep(steps, i, by))} onRemove={() => setSteps(removeStep(steps, s.id))}
                  onRetype={(t) => setStep(i, retypeStep(s, t, steps, approvers, attributes))} />
              </li>
            ))}
          </ol>
          <div className="row tight wrap">
            <label className="sr-only" htmlFor="wf-add-step">Type of the step to add</label>
            <select id="wf-add-step" className="input" value="" disabled={steps.length >= LIMITS.steps}
              onChange={(e) => e.target.value && setSteps([...steps, blankStep(e.target.value as WorkflowStepType, steps, approvers, attributes)])}>
              <option value="">Add a step…</option>
              {STEP_TYPES.filter((t) => vocab.step_types.includes(t.id)).map((t) => <option key={t.id} value={t.id}>{t.label}: {t.hint}</option>)}
            </select>
          </div>
        </fieldset>

        {!readOnly && (
          <div role="status" aria-live="polite" className="stack-sm">
            {textProblem && changed && <p className="hint err">{textProblem}</p>}
            {local.filter((p) => p.step === "").map((p, i) => <p key={i} className="hint err">{p.message}</p>)}
            {(issues ?? []).filter((p) => !p.step).map((p, i) => <p key={i} className="hint err">{p.message}</p>)}
            {local.length === 0 && issues && issues.length === 0 && steps.length > 0 && <p className="hint">The definition is valid: no loops, every step is reachable, every path approves.</p>}
          </div>
        )}
        {err && <p className="hint err" role="alert">{err}</p>}

        {w && !retired && <Assignments w={w} vocab={vocab} manage={manage} onSaved={() => onSaved(w.id)} />}
        {!w && <p className="xs faint">Save the workflow first, then choose what it routes.</p>}

        {w && (
          <section className="stack-sm" aria-label="Versions">
            <h3 className="h-sm">Versions</h3>
            {!detail.data ? <p className="small muted">{detail.error?.message ?? "Loading…"}</p> : (
              <ul className="stack-sm" style={{ paddingLeft: 16 }}>
                {detail.data.versions.map((v) => (
                  <li key={v.version} className="small">v{v.version}{v.version === w.version ? " (current)" : ""}: {v.name}, {v.steps.length} step{v.steps.length === 1 ? "" : "s"}</li>
                ))}
              </ul>
            )}
            <p className="xs faint">Last saved by {w.updated_by}, {fmtDate(w.updated_at)}.</p>
          </section>
        )}
      </div>
    </SidePanel>
  );
}

function StepEditor({ s, index, steps, vocab, approvers, attributes, names, questionnaires, groups, problems, onChange, onMove, onRemove, onRetype }: {
  s: WorkflowStep; index: number; steps: WorkflowStep[]; vocab: Vocab; approvers: string[]; attributes: string[];
  names: { group: (id: string) => string; questionnaire: (id: string) => string };
  questionnaires: { id: string; title: string }[]; groups: GrpGroup[]; problems: { message: string }[];
  onChange: (s: WorkflowStep) => void; onMove: (by: -1 | 1) => void; onRemove: () => void; onRetype: (t: WorkflowStepType) => void;
}) {
  const n = index + 1;
  const other = steps.filter((x) => x.id !== s.id);
  const jump = (label: string, value: string, set: (v: string) => void, required: boolean) => (
    <label className="field">{label}
      <select className="input" value={value} onChange={(e) => set(e.target.value)}>
        {required ? <option value="">Choose…</option> : <option value="">The next step in the list</option>}
        {other.map((x) => <option key={x.id} value={x.id}>{x.id}: {describeStep(x, names)}</option>)}
        <option value={END}>End of the workflow</option>
      </select>
    </label>
  );
  const groupPicker = (value: string | undefined, set: (v: string) => void) => (
    <label className="field">Group
      <select className="input" value={value ?? ""} onChange={(e) => set(e.target.value)}>
        <option value="">Choose a group…</option>
        {groups.map((g) => <option key={g.id} value={g.id}>{g.display_name || g.name}</option>)}
        {value && !groups.some((g) => g.id === value) && <option value={value}>{value}</option>}
      </select>
    </label>
  );
  const when = s.when;
  const valuesFor = when ? ATTRIBUTE_VALUES[when.attribute] : undefined;
  return (
    <fieldset className="card stack-sm" style={{ margin: 0, minWidth: 0 }} aria-describedby={problems.length ? `wf-p-${s.id}` : undefined}>
      <legend className="small"><b>Step {n}</b> · {stepTypeLabel(s.type)} <span className="faint">({s.id})</span></legend>
      <p className="small muted">{describeStep(s, names)}</p>
      <label className="field">Step type
        <select className="input" value={s.type} onChange={(e) => onRetype(e.target.value as WorkflowStepType)}>
          {STEP_TYPES.filter((t) => vocab.step_types.includes(t.id)).map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
        </select>
      </label>
      <label className="field">Label (optional)
        <input className="input" value={s.name ?? ""} maxLength={LIMITS.name} onChange={(e) => onChange({ ...s, name: e.target.value })} />
      </label>

      {s.type === "approval" && (
        <>
          <label className="field">Who approves
            <select className="input" value={s.approver ?? ""} onChange={(e) => onChange({ ...s, approver: e.target.value, ...(e.target.value === "group" ? {} : { group_id: undefined }) })}>
              {approvers.map((a) => <option key={a} value={a}>{APPROVER_LABEL[a] ?? a}</option>)}
            </select>
          </label>
          {s.approver === "group" && groupPicker(s.group_id, (v) => onChange({ ...s, group_id: v }))}
          <label className="field">Escalate to access approvers after (hours, optional)
            <input className="input" inputMode="numeric" style={{ maxWidth: 140 }} value={s.escalate_after_hours ? String(s.escalate_after_hours) : ""} placeholder="48"
              onChange={(e) => { const v = Number(e.target.value.replace(/\D/g, "")); onChange({ ...s, escalate_after_hours: v > 0 ? Math.min(v, LIMITS.hours) : undefined }); }} />
          </label>
        </>
      )}
      {s.type === "questionnaire" && (
        <label className="field">Questionnaire
          <select className="input" value={s.questionnaire_id ?? ""} onChange={(e) => onChange({ ...s, questionnaire_id: e.target.value })}>
            <option value="">Choose a questionnaire…</option>
            {questionnaires.map((q) => <option key={q.id} value={q.id}>{q.title}</option>)}
            {s.questionnaire_id && !questionnaires.some((q) => q.id === s.questionnaire_id) && <option value={s.questionnaire_id}>{s.questionnaire_id}</option>}
          </select>
          <span className="hint">Answered by the requester when the request is filed.</span>
        </label>
      )}
      {s.type === "notify" && (
        <>
          <label className="field">Tell
            <select className="input" value={s.notify ?? ""} onChange={(e) => onChange({ ...s, notify: e.target.value, ...(e.target.value === "group" ? {} : { group_id: undefined }) })}>
              {vocab.notify.map((a) => <option key={a} value={a}>{NOTIFY_LABEL[a] ?? a}</option>)}
            </select>
          </label>
          {s.notify === "group" && groupPicker(s.group_id, (v) => onChange({ ...s, group_id: v }))}
          <label className="field">Message (optional)
            <textarea className="input" rows={2} maxLength={LIMITS.message} value={s.message ?? ""} onChange={(e) => onChange({ ...s, message: e.target.value })} />
          </label>
        </>
      )}
      {s.type === "wait" && (
        <label className="field">Hold the next approval for (hours)
          <input className="input" inputMode="numeric" style={{ maxWidth: 140 }} value={s.hours ? String(s.hours) : ""}
            onChange={(e) => { const v = Number(e.target.value.replace(/\D/g, "")); onChange({ ...s, hours: v > 0 ? Math.min(v, LIMITS.hours) : undefined }); }} />
          <span className="hint">The approval opens after this time. Its approvers are not emailed when it opens; it shows in their inbox.</span>
        </label>
      )}
      {s.type === "condition" && when && (
        <>
          <div className="row tight wrap">
            <label className="field">If
              <select className="input" value={when.attribute} onChange={(e) => onChange({ ...s, when: { ...when, attribute: e.target.value, values: [""] } })}>
                {attributes.map((a) => <option key={a} value={a}>{ATTRIBUTE_LABEL[a] ?? a}</option>)}
              </select>
            </label>
            <label className="field">Test
              <select className="input" value={when.op} onChange={(e) => onChange({ ...s, when: { ...when, op: e.target.value as typeof when.op, values: when.values.slice(0, e.target.value === "eq" || e.target.value === "ne" ? 1 : undefined) } })}>
                {vocab.ops.map((o) => <option key={o} value={o}>{OP_LABEL[o] ?? o}</option>)}
              </select>
            </label>
            {valuesFor && (when.op === "eq" || when.op === "ne") ? (
              <label className="field">Value
                <select className="input" value={when.values[0] ?? ""} onChange={(e) => onChange({ ...s, when: { ...when, values: [e.target.value] } })}>
                  <option value="">Choose…</option>
                  {valuesFor.map((v) => <option key={v} value={v}>{v}</option>)}
                </select>
              </label>
            ) : (
              <label className="field">{when.op === "in" || when.op === "not_in" ? "Values, comma separated" : "Value"}
                <input className="input" value={when.values.join(", ")} onChange={(e) => onChange({ ...s, when: { ...when, values: when.op === "in" || when.op === "not_in" ? e.target.value.split(",").map((v) => v.trim()) : [e.target.value] } })} />
              </label>
            )}
          </div>
          <p className="xs faint">A request without this attribute counts as not matching.</p>
          {jump("When it holds, go to", s.then ?? "", (v) => onChange({ ...s, then: v }), true)}
          {jump("Otherwise, go to", s.else ?? "", (v) => onChange({ ...s, else: v }), true)}
        </>
      )}
      {s.type === "provisioning" && <p className="xs faint">After the last approval, Tessera asks the provisioning engine to add the entitlement in the target system when its connection has write-back on. Service-account requests always provision.</p>}
      {s.type !== "condition" && jump("After this step, go to", s.next ?? "", (v) => onChange({ ...s, next: v || undefined }), false)}
      <p className="xs faint">Goes on to: {flowLabel(steps, index)}</p>
      {problems.length > 0 && <ul id={`wf-p-${s.id}`} className="stack-sm" style={{ paddingLeft: 16 }} role="status">{problems.map((p, i) => <li key={i} className="hint err">{p.message}</li>)}</ul>}
      <div className="row tight">
        <Button size="sm" variant="ghost" icon={<ArrowUp size={14} />} label={`Move step ${n} up`} disabled={index === 0} onClick={() => onMove(-1)} />
        <Button size="sm" variant="ghost" icon={<ArrowDown size={14} />} label={`Move step ${n} down`} disabled={index === steps.length - 1} onClick={() => onMove(1)} />
        <Button size="sm" variant="ghost" icon={<Trash2 size={14} />} label={`Remove step ${n}`} onClick={onRemove} />
      </div>
    </fieldset>
  );
}

/** What the workflow routes: the request types of its scope and, for access workflows, catalog items. */
function Assignments({ w, vocab, manage, onSaved }: { w: Workflow; vocab: Vocab; manage: boolean; onSaved: () => void }) {
  const toast = useToast();
  const catalog = useApi<CatalogView>(w.scope === "access" ? "/catalog?all=1" : null);
  const [targets, setTargets] = useState<WorkflowTarget[]>(w.targets);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const items = useMemo(() => (catalog.data?.items ?? []).filter((c) => c.id).map((c) => ({ id: c.id!, name: `${c.group.system}:${c.group.name}` })), [catalog.data]);
  const itemName = (id: string) => items.find((i) => i.id === id)?.name ?? id;
  const has = (kind: WorkflowTarget["kind"], id: string) => targets.some((t) => t.kind === kind && t.target_id === id);
  const toggleType = (id: string) => setTargets(has("request_type", id) ? targets.filter((t) => !(t.kind === "request_type" && t.target_id === id)) : [...targets, { kind: "request_type", target_id: id }]);
  const key = (ts: WorkflowTarget[]) => JSON.stringify(ts.map((t) => t.kind + ":" + t.target_id).sort());
  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      await wfApi.assign(w.id, targets);
      toast("Saved what it routes");
      onSaved();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="stack-sm" aria-label="What it routes">
      <h3 className="h-sm">What it routes</h3>
      <p className="xs faint">One workflow per target. A catalog item's own workflow wins over the access request type's. A target with none keeps its approval policy.</p>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!manage}>
        <legend className="sr-only">Request types</legend>
        {vocab.request_types[w.scope].map((t) => (
          <label key={t} className="row tight small">
            <input type="checkbox" checked={has("request_type", t)} onChange={() => toggleType(t)} /> {REQUEST_TYPE_LABEL[t] ?? t}
          </label>
        ))}
        {w.scope === "access" && (
          <label className="field">Catalog item
            <select className="input" value="" onChange={(e) => e.target.value && !has("catalog_item", e.target.value) && setTargets([...targets, { kind: "catalog_item", target_id: e.target.value }])}>
              <option value="">Add…</option>
              {items.filter((i) => !has("catalog_item", i.id)).map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}
            </select>
          </label>
        )}
      </fieldset>
      {targets.some((t) => t.kind === "catalog_item") && (
        <ul className="row tight wrap" aria-label="Catalog items" style={{ listStyle: "none", padding: 0, margin: 0 }}>
          {targets.filter((t) => t.kind === "catalog_item").map((t) => (
            <li key={t.target_id}>
              <Chip>{itemName(t.target_id)}
                {manage && <button type="button" className="btn ghost sm icon" style={{ height: 18, width: 18 }} aria-label={`Stop routing ${itemName(t.target_id)}`}
                  onClick={() => setTargets(targets.filter((x) => x !== t))}><X size={12} /></button>}
              </Chip>
            </li>
          ))}
        </ul>
      )}
      {err && <p className="hint err" role="alert">{err}</p>}
      {manage && <div><Button size="sm" onClick={save} disabled={busy || key(targets) === key(w.targets)}>Save what it routes</Button></div>}
    </section>
  );
}
