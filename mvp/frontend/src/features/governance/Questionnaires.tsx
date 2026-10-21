import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ClipboardList, Plus, Trash2, X } from "lucide-react";
import {
  CatalogView, Campaign as CampaignT, Question, QuestionType, Questionnaire, QuestionnaireDetail, QuestionnaireList, QuestionnaireSpec, QuestionnaireTarget,
  RolesView, fmtDate, questionnaires as qApi, questionnairesPath, relTime, useApi,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Chip, Column, DataTable, EmptyState, GovernanceTabs, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { LIMITS, QUESTION_TYPES, askedOf, blankQuestion, cleanSpec, optionsText, parseOptions, retype, sameSpec, specError, targetLabel, typeLabel } from "./questionnaireModel";

/**
 * Governance → Questionnaires (issue #298): forms attached to requests and review decisions. A
 * questionnaire has ordered questions (short and long text, single and multiple choice, yes or no,
 * date), each required or not, with simple limits. Saving an edit makes the next version; answers
 * keep pointing at the version they were given against. A questionnaire is attached to catalog items
 * and business roles (the requester answers at submit), to the privileged tier (every privileged item
 * and high-risk role) or to a review campaign (the reviewer answers with each decision). Creating,
 * editing and attaching need catalog.manage and are audited; the server validates every answer.
 */
export function Questionnaires() {
  const { can } = useSession();
  const manage = can("catalog.manage");
  const list = useApi<QuestionnaireList>(manage ? questionnairesPath : null);
  const [selected, setSelected] = useSelected();
  const rows = list.data?.questionnaires ?? null;
  const creating = selected === "new";
  const current = rows?.find((q) => q.id === selected) ?? null;
  const cols: Column<Questionnaire>[] = [
    { id: "title", header: "Questionnaire", sort: (q) => q.title, cell: (q) => <span className="name-link">{q.title}</span> },
    { id: "version", header: "Version", num: true, sort: (q) => q.version, cell: (q) => `v${q.version}` },
    { id: "status", header: "Status", sort: (q) => q.status, cell: (q) => <Badge tone={q.status === "active" ? "ok" : "outline"}>{q.status === "active" ? "Active" : "Retired"}</Badge> },
    { id: "questions", header: "Questions", num: true, sort: (q) => q.questions.length, cell: (q) => q.questions.length, hideNarrow: true },
    { id: "asked", header: "Asked of", sort: (q) => askedOf(q.targets), cell: (q) => <span className="small">{askedOf(q.targets)}</span>, hideNarrow: true },
    { id: "updated", header: "Updated", sort: (q) => q.updated_at, cell: (q) => <span className="small faint nowrap" title={fmtDate(q.updated_at)}>{relTime(q.updated_at)}</span>, hideNarrow: true },
  ];
  return (
    <Page
      title="Questionnaires"
      crumbs={[["Governance", "/governance/policies"], ["Questionnaires"]]}
      sub="Forms people answer when they request access, and reviewers answer with a decision. Approvers see the answers; the audit trail records their hash and the version."
      tabs={<GovernanceTabs />}
    >
      {!manage && <Callout tone="neutral">Questionnaires are managed by people who hold catalog.manage.</Callout>}
      {list.error && <Callout tone="bad">{list.error.message}</Callout>}
      {manage && (
        <DataTable
          id="questionnaires"
          rows={rows}
          error={list.error}
          rowKey={(q) => q.id}
          columns={cols}
          searchText={(q) => `${q.title} ${q.description} ${askedOf(q.targets)}`}
          searchPlaceholder="Search questionnaires…"
          filters={[{ id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "retired", label: "Retired" }], get: (q) => q.status }]}
          commands={[{ label: "New questionnaire", icon: <Plus size={16} />, onClick: () => setSelected("new") }]}
          onRefresh={list.reload}
          rowLabel={(q) => q.title}
          onRowClick={(q) => setSelected(q.id)}
          activeKey={current?.id ?? null}
          empty={<EmptyState title="No questionnaires yet" icon={<ClipboardList size={18} />}>Create one, then attach it to a catalog item, a role, privileged requests or an access review.</EmptyState>}
        />
      )}
      {manage && (creating || current) && (
        <Editor key={creating ? "new" : `${current!.id}-${current!.version}-${current!.status}`} q={creating ? null : current} onClose={() => setSelected(null)}
          onSaved={(id) => { list.reload(); if (id) setSelected(id); }} />
      )}
    </Page>
  );
}

const blank: QuestionnaireSpec = { title: "", description: "", questions: [] };

function Editor({ q, onClose, onSaved }: { q: Questionnaire | null; onClose: () => void; onSaved: (id?: string) => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const detail = useApi<QuestionnaireDetail>(q ? `${questionnairesPath}/${encodeURIComponent(q.id)}` : null);
  const saved: QuestionnaireSpec = q ?? blank;
  const [draft, setDraft] = useState<QuestionnaireSpec>({ title: saved.title, description: saved.description, questions: saved.questions });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const retired = q?.status === "retired";
  const problem = specError(draft);
  const changed = !q || !sameSpec(draft, saved);
  const setQuestion = (i: number, next: Question) => setDraft((d) => ({ ...d, questions: d.questions.map((x, j) => (j === i ? next : x)) }));
  const move = (i: number, by: -1 | 1) => setDraft((d) => {
    const qs = d.questions.slice();
    [qs[i], qs[i + by]] = [qs[i + by], qs[i]];
    return { ...d, questions: qs };
  });

  const save = async () => {
    if (problem || busy || retired) return;
    setBusy(true);
    setErr(null);
    try {
      const spec = cleanSpec(draft);
      if (q) {
        const r = await qApi.edit(q.id, q.version, spec);
        toast(`Saved as version ${r.version}`);
        onSaved(q.id);
      } else {
        const r = await qApi.create(spec);
        toast("Questionnaire created");
        onSaved(r.id);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const retire = async () => {
    if (!q) return;
    const ok = await confirm({
      title: `Retire ${q.title}?`, body: "It is no longer asked anywhere, and its attachments are removed. Answers already given stay with their requests and decisions.",
      confirmLabel: "Retire", danger: true,
    });
    if (ok == null) return;
    try {
      await qApi.retire(q.id);
      toast("Questionnaire retired");
      onSaved(q.id);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };

  return (
    <SidePanel
      title={q ? q.title : "New questionnaire"}
      sub={q && <span className="small muted">Version {q.version} · {retired ? "retired" : "active"}</span>}
      onClose={onClose}
      footer={(
        <div className="row tight">
          <Button variant="primary" size="sm" onClick={save} disabled={!!problem || !changed || busy || retired}>{q ? "Save as a new version" : "Create"}</Button>
          {q && !retired && <Button size="sm" variant="danger" icon={<Trash2 size={14} />} onClick={retire} disabled={busy}>Retire</Button>}
        </div>
      )}
    >
      <div className="stack">
        {retired && <Callout tone="neutral">This questionnaire is retired. It cannot be edited or attached.</Callout>}
        <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }} disabled={retired}>
          <legend><h3 className="h-sm">Details</h3></legend>
          <label className="field">Title
            <input className="input" value={draft.title} maxLength={LIMITS.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} />
          </label>
          <label className="field">Description (optional)
            <textarea className="input" rows={2} value={draft.description} maxLength={LIMITS.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} aria-describedby="qn-desc-hint" />
            <span className="hint" id="qn-desc-hint">Shown above the questions.</span>
          </label>
        </fieldset>

        <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }} disabled={retired}>
          <legend><h3 className="h-sm">Questions</h3></legend>
          {draft.questions.length === 0 && <p className="small muted">No questions yet.</p>}
          {draft.questions.map((x, i) => (
            <QuestionEditor key={`${x.id}-${x.type}`} q={x} index={i} count={draft.questions.length}
              onChange={(n) => setQuestion(i, n)} onMove={(by) => move(i, by)} onRemove={() => setDraft((d) => ({ ...d, questions: d.questions.filter((_, j) => j !== i) }))} />
          ))}
          <div className="row tight wrap">
            <label className="sr-only" htmlFor="qn-add-type">Type of the question to add</label>
            <select id="qn-add-type" className="input" value="" onChange={(e) => e.target.value && setDraft((d) => ({ ...d, questions: [...d.questions, blankQuestion(e.target.value as QuestionType, d.questions)] }))}
              disabled={draft.questions.length >= LIMITS.questions}>
              <option value="">Add a question…</option>
              {QUESTION_TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          </div>
        </fieldset>

        {err && <p className="hint err" role="alert">{err}</p>}
        {problem && changed && <p className="hint err" role="status">{problem}</p>}
        {q && q.status === "active" && <Targets q={q} onSaved={() => onSaved(q.id)} />}
        {!q && <p className="xs faint">Save the questionnaire first, then choose where it is asked.</p>}

        {q && (
          <section className="stack-sm" aria-label="Versions">
            <h3 className="h-sm">Versions</h3>
            {!detail.data ? <p className="small muted">{detail.error?.message ?? "Loading…"}</p> : (
              <ul className="stack-sm" style={{ paddingLeft: 16 }}>
                {detail.data.versions.map((v) => (
                  <li key={v.version} className="small">v{v.version}{v.version === q.version ? " (current)" : ""}: {v.title}, {v.questions.length} question{v.questions.length === 1 ? "" : "s"}</li>
                ))}
              </ul>
            )}
            <p className="xs faint">Last saved by {q.updated_by}, {fmtDate(q.updated_at)}.</p>
          </section>
        )}
      </div>
    </SidePanel>
  );
}

function QuestionEditor({ q, index, count, onChange, onMove, onRemove }: {
  q: Question; index: number; count: number; onChange: (q: Question) => void; onMove: (by: -1 | 1) => void; onRemove: () => void;
}) {
  const n = index + 1;
  const choice = q.type === "single_choice" || q.type === "multi_choice";
  const text = q.type === "short_text" || q.type === "long_text";
  const [opt, setOpt] = useState(optionsText((q.options ?? []).filter(Boolean)));
  const hint = QUESTION_TYPES.find((t) => t.id === q.type)?.hint;
  return (
    <fieldset className="card stack-sm" style={{ margin: 0, minWidth: 0 }}>
      <legend className="small"><b>Question {n}</b> · {typeLabel(q.type)}</legend>
      <label className="field">Question
        <input className="input" value={q.text} maxLength={LIMITS.questionText} onChange={(e) => onChange({ ...q, text: e.target.value })} />
      </label>
      <label className="field">Type
        <select className="input" value={q.type} onChange={(e) => onChange(retype(q, e.target.value as QuestionType))} aria-describedby={`qn-type-${index}`}>
          {QUESTION_TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
        </select>
        <span className="hint" id={`qn-type-${index}`}>{hint}</span>
      </label>
      <label className="field">Help text (optional)
        <input className="input" value={q.help ?? ""} maxLength={LIMITS.help} onChange={(e) => onChange({ ...q, help: e.target.value })} />
      </label>
      {choice && (
        <label className="field">Options, one per line
          <textarea className="input" rows={4} value={opt} onChange={(e) => { setOpt(e.target.value); onChange({ ...q, options: parseOptions(e.target.value) }); }} aria-describedby={`qn-opt-${index}`} />
          <span className="hint" id={`qn-opt-${index}`}>2 to {LIMITS.options} options, each different.</span>
        </label>
      )}
      {text && (
        <label className="field">Maximum length (optional)
          <input className="input" inputMode="numeric" style={{ maxWidth: 140 }} value={q.max_length ? String(q.max_length) : ""} placeholder={q.type === "long_text" ? "2000" : "200"}
            onChange={(e) => { const v = Number(e.target.value.replace(/\D/g, "")); onChange({ ...q, max_length: v > 0 ? v : undefined }); }} aria-describedby={`qn-max-${index}`} />
          <span className="hint" id={`qn-max-${index}`}>Characters; at most {q.type === "long_text" ? LIMITS.longText : LIMITS.shortText}.</span>
        </label>
      )}
      <label className="row tight small"><input type="checkbox" checked={q.required} onChange={(e) => onChange({ ...q, required: e.target.checked })} /> An answer is required</label>
      <div className="row tight">
        <Button size="sm" variant="ghost" icon={<ArrowUp size={14} />} label={`Move question ${n} up`} disabled={index === 0} onClick={() => onMove(-1)} />
        <Button size="sm" variant="ghost" icon={<ArrowDown size={14} />} label={`Move question ${n} down`} disabled={index === count - 1} onClick={() => onMove(1)} />
        <Button size="sm" variant="ghost" icon={<Trash2 size={14} />} label={`Remove question ${n}`} onClick={onRemove} />
      </div>
    </fieldset>
  );
}

/** Where the questionnaire is asked: the privileged tier, catalog items, business roles and review campaigns. */
function Targets({ q, onSaved }: { q: Questionnaire; onSaved: () => void }) {
  const toast = useToast();
  const catalog = useApi<CatalogView>("/catalog?all=1");
  const roles = useApi<RolesView>("/roles");
  const campaigns = useApi<CampaignT[]>("/reviews/campaigns");
  const [targets, setTargets] = useState<QuestionnaireTarget[]>(q.targets);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const options = useMemo(() => ({
    catalog_item: (catalog.data?.items ?? []).filter((c) => c.id).map((c) => ({ id: c.id!, name: `${c.group.system}:${c.group.name}` })),
    business_role: (roles.data?.roles ?? []).filter((r) => r.status === "active").map((r) => ({ id: r.id, name: r.name })),
    review_campaign: (campaigns.data ?? []).map((c) => ({ id: String(c.id), name: c.name })),
  }), [catalog.data, roles.data, campaigns.data]);
  const names = useMemo(() => {
    const m: Record<string, string> = {};
    for (const [kind, list] of Object.entries(options)) for (const o of list) m[`${kind}:${o.id}`] = o.name;
    return m;
  }, [options]);

  const has = (kind: QuestionnaireTarget["kind"], id: string) => targets.some((t) => t.kind === kind && t.target_id === id);
  const add = (kind: QuestionnaireTarget["kind"], id: string) => id && !has(kind, id) && setTargets([...targets, { kind, target_id: id }]);
  const privileged = has("privileged", "*");
  const same = JSON.stringify([...targets].sort((a, b) => (a.kind + a.target_id).localeCompare(b.kind + b.target_id))) ===
    JSON.stringify([...q.targets].sort((a, b) => (a.kind + a.target_id).localeCompare(b.kind + b.target_id)));

  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      await qApi.attach(q.id, targets);
      toast("Saved where it is asked");
      onSaved();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const picker = (kind: "catalog_item" | "business_role" | "review_campaign", label: string) => (
    <label className="field">{label}
      <select className="input" value="" onChange={(e) => add(kind, e.target.value)}>
        <option value="">Add…</option>
        {options[kind].filter((o) => !has(kind, o.id)).map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
      </select>
    </label>
  );
  return (
    <section className="stack-sm" aria-label="Where it is asked">
      <h3 className="h-sm">Where it is asked</h3>
      <p className="xs faint">One questionnaire per place. Requesters answer at submit; reviewers answer with each decision of a campaign.</p>
      <label className="row tight small">
        <input type="checkbox" checked={privileged} onChange={(e) => setTargets(e.target.checked ? [...targets, { kind: "privileged", target_id: "*" }] : targets.filter((t) => t.kind !== "privileged"))} />
        Every privileged item and high-risk role
      </label>
      {picker("catalog_item", "Catalog item")}
      {picker("business_role", "Business role")}
      {picker("review_campaign", "Access review campaign")}
      {targets.filter((t) => t.kind !== "privileged").length > 0 && (
        <ul className="row tight wrap" aria-label="Attached to" style={{ listStyle: "none", padding: 0, margin: 0 }}>
          {targets.filter((t) => t.kind !== "privileged").map((t) => (
            <li key={t.kind + t.target_id}>
              <Chip>{targetLabel(t, names)}
                <button type="button" className="btn ghost sm icon" style={{ height: 18, width: 18 }} aria-label={`Detach ${targetLabel(t, names)}`}
                  onClick={() => setTargets(targets.filter((x) => x !== t))}><X size={12} /></button>
              </Chip>
            </li>
          ))}
        </ul>
      )}
      {err && <p className="hint err" role="alert">{err}</p>}
      <div><Button size="sm" onClick={save} disabled={busy || same}>Save where it is asked</Button></div>
    </section>
  );
}
