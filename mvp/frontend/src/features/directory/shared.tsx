/** Drawers shared by the Directory lists: CSV import preview and the Preview "New / Edit" form. */
import { FormEvent, ReactNode, useRef, useState } from "react";
import { FileUp } from "lucide-react";
import { usePersona } from "../../app/persona";
import { Button, Callout, Drawer, PreviewBadge, useToast } from "../../components";
import { parseCsv } from "../../components/csv";
import { mockIdentityOps, mockObjects } from "../../mocks";

/**
 * Validates a CSV against the expected columns and shows the first rows before anything is
 * imported. Import itself is Preview: rows are counted and logged in this browser only.
 */
export function ImportDrawer({ kind, label, columns, rows: initial, fileName: initialName, onClose }: {
  kind: string;
  label: string;
  /** Expected header names, lower case. The first one is required. */
  columns: string[];
  rows?: Record<string, string>[];
  fileName?: string;
  onClose: () => void;
}) {
  const { actor } = usePersona();
  const toast = useToast();
  const [rows, setRows] = useState<Record<string, string>[] | null>(initial ?? null);
  const [fileName, setFileName] = useState(initialName ?? "");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const required = columns[0];
  const missing = rows ? rows.filter((r) => !r[required]).length : 0;
  const unknown = rows?.[0] ? Object.keys(rows[0]).filter((k) => !columns.includes(k)) : [];

  const pick = async (f: File | undefined) => {
    if (!f) return;
    setFileName(f.name);
    setRows(parseCsv(await f.text()));
  };
  const run = async () => {
    if (!rows) return;
    setBusy(true);
    const ok = rows.length - missing;
    await mockIdentityOps.importRows(kind, ok, actor);
    setBusy(false);
    toast(`${ok} ${label} queued for import (preview)`);
    onClose();
  };

  return (
    <Drawer
      title={`Import ${label}`}
      sub={<span className="row tight">From a CSV file with a header row <PreviewBadge /></span>}
      onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!rows?.length || busy || missing === rows.length} onClick={run}>Import {rows ? rows.length - missing : ""} rows</Button></>}
    >
      <div className="stack">
        <div className="small muted">
          Expected columns: {columns.map((c, i) => <code key={c}>{c}{i === 0 ? " (required)" : ""}</code>).reduce<ReactNode[]>((a, c, i) => (i ? [...a, ", ", c] : [c]), [])}.
          Unknown columns are ignored.
        </div>
        <input ref={fileRef} type="file" accept=".csv,text/csv" hidden onChange={(e) => pick(e.target.files?.[0])} tabIndex={-1} aria-hidden />
        <div className="row">
          <Button icon={<FileUp size={15} />} onClick={() => fileRef.current?.click()} data-autofocus>{rows ? "Choose another file" : "Choose CSV file"}</Button>
          {fileName && <span className="small muted truncate">{fileName}</span>}
        </div>
        {rows && rows.length === 0 && <Callout tone="bad">That file has no data rows. The first line must be a header row.</Callout>}
        {rows && rows.length > 0 && (
          <>
            <div className="stat-row">
              <div className="s"><b className="tnum">{rows.length}</b><span>rows read</span></div>
              <div className="s"><b className="tnum" style={{ color: missing ? "var(--critical)" : undefined }}>{missing}</b><span>missing “{required}”</span></div>
            </div>
            {unknown.length > 0 && <Callout tone="neutral">Ignoring column{unknown.length > 1 ? "s" : ""}: {unknown.join(", ")}</Callout>}
            <div className="card flush">
              <div className="table-scroll">
                <table>
                  <thead><tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
                  <tbody>
                    {rows.slice(0, 8).map((r, i) => (
                      <tr key={i}>{columns.map((c) => <td key={c} className="small">{r[c] || <span className="faint">-</span>}</td>)}</tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {rows.length > 8 && <div className="small faint" style={{ padding: "8px 14px" }}>and {rows.length - 8} more</div>}
            </div>
          </>
        )}
      </div>
    </Drawer>
  );
}

export interface FieldDef {
  id: string;
  label: string;
  required?: boolean;
  options?: string[];
  placeholder?: string;
  hint?: string;
  textarea?: boolean;
}

/**
 * Create / edit form for objects without a write endpoint. It validates and records the change
 * in this browser (Preview) so the flow can be tried end to end.
 */
export function PreviewFormDrawer({ title, kind, fields, initial, verb = "create", onClose, note }: {
  title: string;
  kind: string;
  fields: FieldDef[];
  initial?: Record<string, string>;
  verb?: "create" | "update";
  onClose: () => void;
  note?: ReactNode;
}) {
  const { actor } = usePersona();
  const toast = useToast();
  const [v, setV] = useState<Record<string, string>>(() => Object.fromEntries(fields.map((f) => [f.id, initial?.[f.id] ?? ""])));
  const [busy, setBusy] = useState(false);
  const invalid = fields.some((f) => f.required && !v[f.id]?.trim());
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (invalid) return;
    setBusy(true);
    const name = v[fields[0].id];
    await mockObjects.save(kind, name, actor, verb);
    setBusy(false);
    toast(`${name} ${verb === "create" ? "created" : "saved"} (preview)`);
    onClose();
  };
  return (
    <Drawer title={title} sub={<PreviewBadge />} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="preview-form" variant="primary" disabled={invalid || busy}>{verb === "create" ? "Create" : "Save changes"}</Button></>}
    >
      <form id="preview-form" className="stack" onSubmit={submit}>
        {note && <Callout tone="neutral">{note}</Callout>}
        {fields.map((f, i) => (
          <label key={f.id} className="field">
            <span>{f.label}{f.required && <span className="faint"> (required)</span>}</span>
            {f.options ? (
              <select className="input" value={v[f.id]} onChange={(e) => setV({ ...v, [f.id]: e.target.value })} data-autofocus={i === 0 || undefined}>
                <option value="">Select…</option>
                {f.options.map((o) => <option key={o}>{o}</option>)}
              </select>
            ) : f.textarea ? (
              <textarea className="input" value={v[f.id]} placeholder={f.placeholder} onChange={(e) => setV({ ...v, [f.id]: e.target.value })} />
            ) : (
              <input className="input" value={v[f.id]} placeholder={f.placeholder} onChange={(e) => setV({ ...v, [f.id]: e.target.value })} data-autofocus={i === 0 || undefined} />
            )}
            {f.hint && <span className="hint">{f.hint}</span>}
          </label>
        ))}
      </form>
    </Drawer>
  );
}

export const uniq = (xs: (string | null | undefined)[]) => [...new Set(xs.filter((x): x is string => !!x))].sort();
export const opts = (xs: string[]) => xs.map((x) => ({ value: x, label: x }));
