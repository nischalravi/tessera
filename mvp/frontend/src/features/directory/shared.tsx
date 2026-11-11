/** Drawers shared by the Directory lists: CSV import into a manual source, and the create / edit form. */
import { FormEvent, Fragment, ReactNode, useEffect, useRef, useState } from "react";
import { FileUp } from "lucide-react";
import { useSession } from "../../app/auth";
import { Button, Callout, Chip, Drawer, useToast } from "../../components";
import {
  ImportPlan, ImportSources, ImportTarget, ManualLookup, OwnershipList, applyDirectoryImport, manualLookupPath, ownedObject, ownershipPath,
  planDirectoryImport, putManualRecord, useApi,
} from "../../api";
import { OwnerForm } from "./owners";
import {
  FORM_FIELDS, FieldDef, KEY_FIELD, checkImportFile, expectedColumns, formMode, claimNote, guardNote, initialValues, managedBy, ownerKindFor, planHeadline,
  resultMessage, slugifySource, toRecordFields,
} from "./importModel";

export type { FieldDef } from "./importModel";

const NEW_SOURCE = "__new";

/**
 * Imports a CSV into a manual source: a system the admin names, never a connector's. The file is sent to the
 * server for a dry run (what would be added, changed and removed, and every bad row), then applied. Applying
 * needs the directory import permission and a fresh sign-in.
 */
export function ImportDrawer({ kind, label, file: initialFile, onClose, onDone }: {
  kind: ImportTarget;
  label: string;
  file?: File | null;
  onClose: () => void;
  onDone?: () => void;
}) {
  const toast = useToast();
  const { can } = useSession();
  const { data: meta } = useApi<ImportSources>("/directory/imports/sources");
  const [file, setFile] = useState<File | null>(initialFile ?? null);
  const [fileErr, setFileErr] = useState<string | null>(null);
  const [source, setSource] = useState("");
  const [newName, setNewName] = useState("");
  const [plan, setPlan] = useState<ImportPlan | null>(null);
  const [planErr, setPlanErr] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const seq = useRef(0);
  const sources = (meta?.sources ?? []).filter((x) => x.system);
  const isNew = source === NEW_SOURCE;
  const system = isNew ? slugifySource(newName) : source;
  const sourceName = isNew ? newName.trim() : "";
  const picked = sources.find((x) => x.system === source) ?? null;
  const cols = expectedColumns(meta?.columns[kind], kind, picked);
  const allowed = can("directory.import");

  useEffect(() => {
    if (initialFile) setFileErr(checkImportFile(initialFile));
  }, [initialFile]);

  useEffect(() => {
    setPlan(null);
    setPlanErr(null);
    if (!file || fileErr || !system || !allowed) return;
    const mine = ++seq.current;
    setChecking(true);
    planDirectoryImport(kind, system, sourceName, file)
      .then((r) => mine === seq.current && setPlan(r.plan))
      .catch((e) => mine === seq.current && setPlanErr(String(e.message ?? e)))
      .finally(() => mine === seq.current && setChecking(false));
  }, [file, fileErr, system, sourceName, kind, allowed]);

  const pick = (f: File | undefined) => {
    if (!f) return;
    setFile(f);
    setFileErr(checkImportFile(f));
    if (fileRef.current) fileRef.current.value = "";
  };
  const apply = async () => {
    if (!file || !system) return;
    setBusy(true);
    setPlanErr(null);
    try {
      const r = await applyDirectoryImport(kind, system, sourceName, file);
      if (r.error) {
        setPlan(r.plan);
        setPlanErr(r.detail ?? "The file was refused.");
        return;
      }
      toast(resultMessage(r, `${label[0].toUpperCase()}${label.slice(1)} from ${system}`));
      onDone?.();
      onClose();
    } catch (e: any) {
      setPlanErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };
  const doable = !!plan && plan.error_count === 0 && plan.added + plan.changed + plan.removed > 0;
  const note = plan ? guardNote(plan) : null;

  return (
    <Drawer
      title={`Import ${label}`}
      sub="From a CSV file with a header row, into a manual source"
      onClose={onClose}
      wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!doable || busy || checking || !allowed} onClick={apply}>{plan && doable ? `Apply ${plan.added + plan.changed + plan.removed} changes` : "Apply"}</Button></>}
    >
      <div className="stack">
        {!allowed && <Callout tone="warn">Importing needs the directory import permission, which tenant admins have.</Callout>}
        <Callout tone="neutral">
          A CSV import never writes to a connector's system. Rows go into a manual source you name, through the same correlation and deletion guard as a connector sync.
          A row missing from a later file is removed only if this source imported it before.
        </Callout>
        <label className="field">
          <span>Manual source</span>
          <select className="input" value={source} onChange={(e) => setSource(e.target.value)} data-autofocus>
            <option value="">Choose a source…</option>
            {sources.map((x) => <option key={x.system} value={x.system}>{x.name === x.system ? x.system : `${x.name} (${x.system})`}</option>)}
            <option value={NEW_SOURCE}>A new manual source…</option>
          </select>
        </label>
        {isNew && (
          <label className="field">
            <span>Name of the new source</span>
            <input className="input" value={newName} placeholder="e.g. HR spreadsheet" maxLength={100} onChange={(e) => setNewName(e.target.value)} />
            <span className="hint">{system ? <>Saved as <code>{system}</code></> : "Use letters or digits."}</span>
          </label>
        )}
        <div className="small muted">
          Columns: {cols.all.map((c, i) => <span key={c}>{i > 0 && ", "}<code>{c}</code>{cols.required.includes(c) ? " (required)" : ""}</span>)}.
          Other columns are ignored. At most {meta ? meta.limits.max_rows.toLocaleString() : "10,000"} rows and 5 MiB, UTF-8.
        </div>
        <input ref={fileRef} type="file" accept=".csv,text/csv" hidden onChange={(e) => pick(e.target.files?.[0])} tabIndex={-1} aria-hidden />
        <div className="row">
          <Button icon={<FileUp size={15} />} onClick={() => fileRef.current?.click()}>{file ? "Choose another file" : "Choose CSV file"}</Button>
          {file && <span className="small muted truncate">{file.name}</span>}
        </div>
        {fileErr && <Callout tone="bad">{fileErr}</Callout>}
        {file && !fileErr && !system && <Callout tone="neutral">Choose or name the manual source to check the file.</Callout>}
        {checking && <div className="small muted" role="status">Checking the file…</div>}
        {planErr && <Callout tone="bad">{planErr}</Callout>}
        {plan && <PlanView plan={plan} note={note} headline={planHeadline(plan)} />}
      </div>
    </Drawer>
  );
}

function PlanView({ plan, note, headline }: { plan: ImportPlan; note: string | null; headline: string }) {
  const claims = claimNote(plan);
  return (
    <div className="stack" aria-live="polite">
      <div className="stat-row">
        <div className="s"><b className="tnum">{plan.rows}</b><span>rows read</span></div>
        <div className="s"><b className="tnum">{plan.added}</b><span>to add</span></div>
        <div className="s"><b className="tnum">{plan.changed}</b><span>to change</span></div>
        <div className="s"><b className="tnum">{plan.removed}</b><span>to remove</span></div>
        <div className="s"><b className="tnum" style={{ color: plan.error_count ? "var(--critical)" : undefined }}>{plan.error_count}</b><span>errors</span></div>
      </div>
      <Callout tone={plan.error_count ? "bad" : "ok"}>{headline}</Callout>
      {note && <Callout tone="warn">{note}</Callout>}
      {claims && (
        <Callout tone="warn">
          {claims.summary}
          <ul className="claims">{claims.lines.slice(0, 20).map((l) => <li key={l}>{l}</li>)}</ul>
          {claims.lines.length > 20 && <span>…and {claims.lines.length - 20} more.</span>}
        </Callout>
      )}
      {plan.errors.length > 0 && (
        <div className="card flush">
          <div className="table-scroll">
            <table>
              <thead><tr><th>Row</th><th>Column</th><th>Problem</th></tr></thead>
              <tbody>{plan.errors.slice(0, 20).map((e, i) => <tr key={i}><td className="tnum small">{e.row || "file"}</td><td className="small">{e.column || <span className="faint">-</span>}</td><td className="small">{e.message}</td></tr>)}</tbody>
            </table>
          </div>
          {plan.error_count > 20 && <div className="small faint" style={{ padding: "8px 14px" }}>and {plan.error_count - 20} more{plan.errors_truncated ? " (not all are listed)" : ""}</div>}
        </div>
      )}
      {plan.error_count === 0 && plan.changes.length > 0 && (
        <div className="card flush">
          <div className="table-scroll">
            <table>
              <thead><tr><th>Change</th><th>Row</th><th>What</th></tr></thead>
              <tbody>{plan.changes.slice(0, 8).map((c, i) => <tr key={i}><td className="small">{c.change}</td><td className="small">{c.label}</td><td className="small">{c.detail || <span className="faint">-</span>}</td></tr>)}</tbody>
            </table>
          </div>
          {plan.added + plan.changed + plan.removed > 8 && <div className="small faint" style={{ padding: "8px 14px" }}>and {plan.added + plan.changed + plan.removed - 8} more</div>}
        </div>
      )}
    </div>
  );
}

/**
 * Create or edit one object. Tessera writes only objects a manual source owns: for an object a connector
 * owns the form is read-only, with "Managed by <system>", and offers only what Tessera itself keeps
 * (an owner, for entitlements and machine identities). A new object goes into a manual source.
 */
export function ObjectFormDrawer({ title, target, id, known, source: sourceHint, human, onClose, onSaved, note }: {
  title: string;
  target: ImportTarget;
  /** The object being edited; absent for a new one. */
  id?: number;
  /** Field values the caller already has, shown read-only when a connector owns the object. */
  known?: Record<string, string>;
  /** Names the source in "Managed by" when the server does not. */
  source?: string;
  /** A person is human; a machine identity has an owner Tessera keeps. */
  human?: boolean;
  onClose: () => void;
  onSaved?: () => void;
  note?: ReactNode;
}) {
  const toast = useToast();
  const { can } = useSession();
  const { data: lookup, error: lookupErr } = useApi<ManualLookup>(id ? manualLookupPath(target, id) : null);
  const { data: meta } = useApi<ImportSources>("/directory/imports/sources");
  const mode = formMode(!!id, lookup);
  const fields = FORM_FIELDS[target];
  const [v, setV] = useState<Record<string, string> | null>(null);
  const [source, setSource] = useState("");
  const [newName, setNewName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [owner, setOwner] = useState(false);
  const ownerKind = ownerKindFor(target, human);
  const { data: owned, reload: reloadOwned } = useApi<OwnershipList>(mode === "readonly" && ownerKind ? ownershipPath(ownerKind) : null);
  const values = v ?? (mode === "create" ? initialValues(target, null) : initialValues(target, lookup, known));
  const sources = (meta?.sources ?? []).filter((x) => x.system);
  const isNew = source === NEW_SOURCE;
  const system = mode === "edit" ? lookup?.system ?? "" : isNew ? slugifySource(newName) : source;
  const locked = (f: FieldDef) => mode === "edit" && f.id === KEY_FIELD[target];
  const invalid = mode === "create" ? !system || fields.some((f) => f.required && !values[f.id]?.trim()) : fields.some((f) => f.required && !values[f.id]?.trim());
  const allowed = can("directory.import");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (invalid || !allowed) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await putManualRecord({ target, system, ...(isNew ? { name: newName.trim() } : {}), fields: toRecordFields(target, values) });
      if (r.error) {
        setErr(r.plan.errors[0]?.message ?? r.detail ?? "The change was refused.");
        return;
      }
      toast(resultMessage(r, mode === "create" ? "Created" : "Saved"));
      onSaved?.();
      onClose();
    } catch (x: any) {
      setErr(String(x.message ?? x));
    } finally {
      setBusy(false);
    }
  };

  if (mode === "readonly") {
    const o = ownerKind && id ? ownedObject(owned, id) ?? { kind: ownerKind, key: String(id), label: known?.name ?? title, primary_owner: null, backup_owner: null, owner_group: null, purpose: "", source: null, updated_at: null } : null;
    return (
      <Drawer title={title} sub={<Chip mono>Managed by {managedBy(lookup, sourceHint)}</Chip>} onClose={onClose}
        footer={<>{o && can("ownership.manage") && <Button onClick={() => setOwner(true)}>{o.primary_owner ? "Change owner" : "Assign owner"}</Button>}<Button variant="primary" onClick={onClose}>Close</Button></>}
      >
        <div className="stack">
          <Callout tone="neutral">
            {managedBy(lookup, sourceHint)} owns these fields, so they are read-only here and a sync would overwrite an edit.
            {o ? " Tessera keeps the owner." : " Tessera keeps no attributes of its own for this object."}
          </Callout>
          <dl className="kv">
            {fields.filter((f) => known?.[f.id]).map((f) => <Fragment key={f.id}><dt>{f.label}</dt><dd>{known?.[f.id]}</dd></Fragment>)}
          </dl>
        </div>
        {owner && o && <OwnerForm obj={o} onClose={() => setOwner(false)} onSaved={() => reloadOwned()} />}
      </Drawer>
    );
  }

  return (
    <Drawer title={title} sub={mode === "edit" ? <Chip mono>Manual source {lookup?.system}</Chip> : "Saved in a manual source"} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="object-form" variant="primary" disabled={invalid || busy || mode === "loading" || !allowed}>{mode === "create" ? "Create" : "Save changes"}</Button></>}
    >
      <form id="object-form" className="stack" onSubmit={submit}>
        {!allowed && <Callout tone="warn">Changing a manually managed object needs the directory import permission, which tenant admins have.</Callout>}
        {note && <Callout tone="neutral">{note}</Callout>}
        {mode === "loading" && !lookupErr && <div className="small muted" role="status">Loading…</div>}
        {lookupErr && <Callout tone="bad">{lookupErr.message}</Callout>}
        {mode === "create" && (
          <>
            <label className="field">
              <span>Manual source <span className="faint">(required)</span></span>
              <select className="input" value={source} onChange={(e) => setSource(e.target.value)} data-autofocus>
                <option value="">Choose a source…</option>
                {sources.map((x) => <option key={x.system} value={x.system}>{x.name === x.system ? x.system : `${x.name} (${x.system})`}</option>)}
                <option value={NEW_SOURCE}>A new manual source…</option>
              </select>
              <span className="hint">Tessera creates objects only in a manual source, never in a connector's system.</span>
            </label>
            {isNew && (
              <label className="field">
                <span>Name of the new source</span>
                <input className="input" value={newName} maxLength={100} placeholder="e.g. HR spreadsheet" onChange={(e) => setNewName(e.target.value)} />
                <span className="hint">{system ? <>Saved as <code>{system}</code></> : "Use letters or digits."}</span>
              </label>
            )}
          </>
        )}
        {mode !== "loading" && fields.map((f, i) => (
          <label key={f.id} className="field">
            <span>{f.label}{f.required && <span className="faint"> (required)</span>}</span>
            {f.options ? (
              <select className="input" value={values[f.id]} disabled={locked(f)} onChange={(e) => setV({ ...values, [f.id]: e.target.value })} data-autofocus={(mode === "edit" && i === 0) || undefined}>
                <option value="">Default</option>
                {f.options.map((o) => <option key={o}>{o}</option>)}
              </select>
            ) : f.textarea ? (
              <textarea className="input" value={values[f.id]} placeholder={f.placeholder} onChange={(e) => setV({ ...values, [f.id]: e.target.value })} />
            ) : (
              <input className="input" value={values[f.id]} disabled={locked(f)} placeholder={f.placeholder} onChange={(e) => setV({ ...values, [f.id]: e.target.value })} data-autofocus={(mode === "edit" && i === 0) || undefined} />
            )}
            {f.hint && <span className="hint">{f.hint}</span>}
          </label>
        ))}
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

export const uniq = (xs: (string | null | undefined)[]) => [...new Set(xs.filter((x): x is string => !!x))].sort();
export const opts = (xs: string[]) => xs.map((x) => ({ value: x, label: x }));
