import { FormEvent, useId, useMemo, useRef, useState } from "react";
import { FileUp, ListChecks, Plus, Save } from "lucide-react";
import { FlatChange, FlatKind, FlatMapping, FlatRowError, FlatTask, FlatUpload, FlatUploadDetail, closeFlatTask, fmtDate, saveFlatMapping, uploadFlatFile, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Column, DataTable, EmptyState, Loading, Page, SidePanel, useSelected, useToast } from "../../components";
import { useModal } from "../../components/overlay";
import { MappingForm, checkFile, emptyForm, errorHelp, formFromMapping, formProblems, headerOf, rowLabel, toBody } from "./flatfileForm";

/**
 * Flat-file import for disconnected applications (issue #105): an app with no connector gets a
 * saved column mapping, its owner uploads CSVs of accounts and of account-entitlement rows, and
 * Tessera computes what changed. Imported accounts correlate, review, show in SoD and leaver
 * plans like any connector's. A leaver or revoke on such an app becomes a manual task that stays
 * open until the next upload shows the access gone.
 *
 * Hiding controls with can() is for usability only: the API enforces every permission.
 */

const KIND_LABEL: Record<FlatKind, string> = { accounts: "Accounts", entitlements: "Entitlements" };
const TASK_LABEL: Record<FlatTask["kind"], string> = { disable_account: "Disable account", remove_entitlement: "Remove entitlement" };
const TASK_TONE = { open: "warning", confirmed: "ok", closed: "neutral" } as const;

export function FlatFiles() {
  const { can } = useSession();
  const [selected, setSelected] = useSelected("app");
  const [creating, setCreating] = useState(false);
  const apps = useApi<{ apps: FlatMapping[] }>("/flatfile/apps");
  const list = apps.data?.apps ?? null;
  const app = list?.find((a) => a.system === selected) ?? null;
  return (
    <Page
      title="Flat-file apps"
      crumbs={[["Settings"], ["Flat-file apps"]]}
      sub="Applications with no connector. Map the columns of their CSV exports once, upload the files, and Tessera keeps their accounts and access in the graph."
      actions={can("flatfile.manage") && <Button variant="primary" icon={<Plus size={14} />} onClick={() => { setCreating(true); setSelected(null); }}>New app</Button>}
    >
      <div className="stack">
        {!list ? <Loading error={apps.error} kind="block" /> : (
          <div className="card stack-sm">
            <label className="field" style={{ maxWidth: 360 }}>
              App
              <select className="input" value={creating ? "" : (selected ?? "")} onChange={(e) => { setCreating(false); setSelected(e.target.value || null); }}>
                <option value="">{list.length ? "Choose an app…" : "No apps yet"}</option>
                {list.map((a) => <option key={a.system} value={a.system}>{a.name} ({a.system})</option>)}
              </select>
            </label>
            {list.length === 0 && !creating && (
              <EmptyState title="No flat-file apps yet" icon={<FileUp size={18} />}>
                {can("flatfile.manage") ? "Choose New app to describe the columns of the first one." : "A tenant admin saves each app's column mapping first."}
              </EmptyState>
            )}
          </div>
        )}
        {(creating || app) && (
          <MappingEditor key={creating ? "new" : app!.system} mapping={creating ? null : app} canEdit={can("flatfile.manage")}
            onSaved={(m) => { setCreating(false); setSelected(m.system); apps.reload(); }} />
        )}
        {app && !creating && <UploadCard app={app} canUpload={can("flatfile.upload")} />}
        <History system={app && !creating ? app.system : null} />
        <Tasks canClose={can("flatfile.close_tasks")} />
      </div>
    </Page>
  );
}

// ---------------------------------------------------------------- mapping

function MappingEditor({ mapping, canEdit, onSaved }: { mapping: FlatMapping | null; canEdit: boolean; onSaved: (m: FlatMapping) => void }) {
  const toast = useToast();
  const [f, setF] = useState<MappingForm>(() => (mapping ? formFromMapping(mapping) : emptyForm()));
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cols, setCols] = useState<string[]>([]);
  const listId = useId();
  const isNew = !mapping;
  const problems = formProblems(f, isNew);
  const set = (k: keyof MappingForm) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const bad = (k: string) => (shown && problems[k] ? problems[k] : undefined);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setShown(true);
    if (Object.keys(problems).length) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await saveFlatMapping(f.system, toBody(f));
      toast(`Saved the mapping of ${saved.name}`);
      onSaved(saved);
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  const sample = async (file: File | undefined) => {
    if (file) setCols(headerOf(await file.slice(0, 8192).text()));
  };
  const field = (k: keyof MappingForm, label: string, opts: { required?: boolean; hint?: string; list?: boolean; disabled?: boolean } = {}) => (
    <label className="field">
      {label}{opts.required && <span className="small muted"> (required)</span>}
      <input className="input" value={f[k] as string} onChange={set(k)} disabled={!canEdit || opts.disabled} list={opts.list ? listId : undefined}
        aria-invalid={!!bad(k)} aria-describedby={bad(k) ? `${listId}-${k}` : undefined} autoComplete="off" />
      {opts.hint && !bad(k) && <span className="hint">{opts.hint}</span>}
      {bad(k) && <span id={`${listId}-${k}`} className="err" role="alert">{problems[k]}</span>}
    </label>
  );
  return (
    <form className="card stack" onSubmit={save} aria-label="Column mapping">
      <div className="spread">
        <h2>{isNew ? "New app" : `Column mapping of ${mapping!.name}`}</h2>
        {mapping && <span className="small muted">Saved {fmtDate(mapping.updated_at)} by {mapping.updated_by}</span>}
      </div>
      {!canEdit && <Callout tone="neutral">Saving a mapping needs the flatfile.manage permission (tenant admins) and a fresh sign-in.</Callout>}
      <div className="grid g2">
        {field("system", "System name", { required: true, disabled: !isNew, hint: isNew ? "Short and permanent, for example payroll. It names the app's accounts everywhere." : undefined })}
        {field("name", "Display name", { required: true })}
        {field("owner", "App owner", { hint: "Who answers questions about this app's access." })}
      </div>
      {canEdit && (
        <div>
          <label className="field" style={{ maxWidth: 420 }}>
            Suggest column names from a sample file
            <input className="input" type="file" accept=".csv,text/csv" onChange={(e) => sample(e.target.files?.[0])} />
            <span className="hint">Only the first line is read, in your browser; nothing is sent.</span>
          </label>
          <datalist id={listId}>{cols.map((c) => <option key={c} value={c} />)}</datalist>
        </div>
      )}
      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend><b>Accounts file</b> <span className="small muted">the column of each field</span></legend>
        {bad("accounts") && <Callout tone="bad">{problems.accounts}</Callout>}
        <div className="grid g2">
          {field("account_id", "Account id", { required: true, list: true, hint: "Unique per account; stays the same between files." })}
          {field("username", "Username", { required: true, list: true })}
          {field("email", "Email", { list: true, hint: "Correlates the account to a person by email." })}
          {field("identity_id", "Person's id", { list: true, hint: "The person's employee id; tried before email." })}
          {field("status", "Status", { list: true, hint: "active, enabled, disabled, inactive, suspended, locked, terminated." })}
        </div>
      </fieldset>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend><b>Entitlements file</b> <span className="small muted">one row per account and entitlement</span></legend>
        <label className="row tight small">
          <input type="checkbox" checked={f.hasEntitlements} disabled={!canEdit} onChange={(e) => setF({ ...f, hasEntitlements: e.target.checked })} /> This app has an entitlements file
        </label>
        {f.hasEntitlements && (
          <>
            {bad("entitlements") && <Callout tone="bad">{problems.entitlements}</Callout>}
            <div className="grid g2">
              {field("e_account_id", "Account id", { required: true, list: true, hint: "Must match an account of the accounts file." })}
              {field("entitlement", "Entitlement", { required: true, list: true, hint: "The role or permission code." })}
              {field("e_name", "Entitlement name", { list: true })}
              {field("privileged", "Privileged", { list: true, hint: "yes or no." })}
            </div>
          </>
        )}
      </fieldset>
      {error && <Callout tone="bad">{error}</Callout>}
      {canEdit && <div><Button type="submit" variant="primary" icon={<Save size={14} />} disabled={busy}>{busy ? "Saving…" : "Save mapping"}</Button></div>}
    </form>
  );
}

// ---------------------------------------------------------------- upload

function UploadCard({ app, canUpload }: { app: FlatMapping; canUpload: boolean }) {
  const toast = useToast();
  const [kind, setKind] = useState<FlatKind>("accounts");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ upload: FlatUploadDetail; confirmed: number } | null>(null);
  const ref = useRef<HTMLInputElement>(null);
  const pick = async (file: File | undefined) => {
    if (!file) return;
    setResult(null);
    const why = checkFile(file);
    if (why) { setError(why); return; }
    setBusy(true);
    setError(null);
    try {
      const r = await uploadFlatFile(app.system, kind, file);
      setResult({ upload: r.upload, confirmed: r.confirmed_tasks.length });
      toast(r.upload.status === "applied" ? `Imported ${file.name}` : `${file.name} was rejected`, { kind: r.upload.status === "applied" ? "ok" : "error" });
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
      if (ref.current) ref.current.value = "";
    }
  };
  return (
    <div className="card stack-sm">
      <h2>Upload a file for {app.name}</h2>
      {!canUpload && <Callout tone="neutral">Uploading needs the flatfile.upload permission (operators and policy admins).</Callout>}
      <p className="small muted" style={{ margin: 0 }}>
        Send the whole export each time: accounts missing from a new accounts file count as removed. Upload accounts before entitlements. A file with any invalid row is rejected whole, with each bad row listed, and changes nothing.
      </p>
      <div className="row">
        <label className="field">
          File type
          <select className="input" value={kind} onChange={(e) => setKind(e.target.value as FlatKind)} disabled={busy}>
            <option value="accounts">Accounts</option>
            <option value="entitlements" disabled={!app.entitlements}>Entitlements{app.entitlements ? "" : " (not mapped)"}</option>
          </select>
        </label>
        <input ref={ref} type="file" accept=".csv,text/csv" hidden onChange={(e) => pick(e.target.files?.[0])} tabIndex={-1} aria-hidden />
        <Button variant="primary" icon={<FileUp size={14} />} disabled={!canUpload || busy} onClick={() => ref.current?.click()} style={{ alignSelf: "flex-end" }}>
          {busy ? "Uploading…" : "Upload CSV"}
        </Button>
      </div>
      {error && <Callout tone="bad">{error}</Callout>}
      {result && (
        <div role="status" aria-live="polite">
          <UploadSummary u={result.upload} />
          {result.confirmed > 0 && <Callout tone="ok">{result.confirmed} manual task(s) confirmed done by this file.</Callout>}
          {result.upload.status === "rejected" && <RowErrors u={result.upload} />}
        </div>
      )}
    </div>
  );
}

function UploadSummary({ u }: { u: FlatUpload }) {
  return u.status === "applied" ? (
    <Callout tone="ok">
      Applied: {u.added} added, {u.removed} removed, {u.changed} changed, {u.unchanged} unchanged ({u.rows_total} rows).
    </Callout>
  ) : (
    <Callout tone="bad">Rejected: {u.rows_rejected > 0 ? `${u.rows_rejected} row(s) failed validation.` : "the file could not be read."} Nothing was imported.</Callout>
  );
}

function RowErrors({ u }: { u: FlatUploadDetail }) {
  if (u.errors.length === 0) return null;
  return (
    <div className="mt-sm">
      <div className="table-scroll">
        <table aria-label="Rows that failed validation">
          <thead><tr><th>Where</th><th>Column</th><th>Problem</th></tr></thead>
          <tbody>
            {u.errors.map((e: FlatRowError, i) => (
              <tr key={i}>
                <td className="nowrap small">{rowLabel(e.row)}</td>
                <td className="small sys">{e.column || "—"}</td>
                <td className="small"><b>{errorHelp(e.code)}</b> <span className="muted">{e.message}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {u.errors_truncated && <p className="small muted">Only the first {u.errors.length} of {u.rows_rejected} rejected rows are listed. Fix these and upload again.</p>}
    </div>
  );
}

// ---------------------------------------------------------------- history

function History({ system }: { system: string | null }) {
  const { data, error, reload } = useApi<{ uploads: FlatUpload[] }>(system ? `/flatfile/uploads?system=${encodeURIComponent(system)}` : "/flatfile/uploads");
  const [sel, setSel] = useSelected("upload");
  const cols: Column<FlatUpload>[] = [
    { id: "at", header: "When", sort: (r) => r.uploaded_at, cell: (r) => <span className="small nowrap">{fmtDate(r.uploaded_at)}</span> },
    { id: "app", header: "App", sort: (r) => r.system, cell: (r) => <span className="small sys">{r.system}</span>, hideNarrow: true },
    { id: "kind", header: "File", sort: (r) => r.kind, cell: (r) => <span className="small">{KIND_LABEL[r.kind]}<br /><span className="xs faint">{r.filename}</span></span> },
    { id: "status", header: "Result", sort: (r) => r.status, cell: (r) => <Badge tone={r.status === "applied" ? "ok" : "critical"}>{r.status === "applied" ? "Applied" : "Rejected"}</Badge> },
    { id: "delta", header: "Delta", csv: (r) => `+${r.added} -${r.removed} ~${r.changed}`, cell: (r) => r.status === "applied" ? <span className="small tnum">+{r.added} −{r.removed} ~{r.changed}</span> : <span className="small tnum">{r.rows_rejected} bad</span> },
    { id: "by", header: "By", sort: (r) => r.uploaded_by, cell: (r) => <span className="small">{r.uploaded_by}</span>, hideNarrow: true },
  ];
  return (
    <section aria-label="Upload history">
      <h2 className="mt-sm" style={{ marginBottom: 8 }}>Upload history</h2>
      <DataTable
        id="flatfile-uploads"
        rows={data?.uploads ?? null}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        initialSort={["at", -1]}
        onRefresh={reload}
        onRowClick={(r) => setSel(r.id)}
        activeKey={sel}
        rowLabel={(r) => `${r.filename} of ${r.uploaded_at}`}
        searchText={(r) => `${r.system} ${r.kind} ${r.filename} ${r.status} ${r.uploaded_by}`}
        searchPlaceholder="Search file name, app or person…"
        filters={[
          { id: "status", label: "Result", options: [{ value: "applied", label: "Applied" }, { value: "rejected", label: "Rejected" }], get: (r) => r.status },
          { id: "kind", label: "File", options: [{ value: "accounts", label: "Accounts" }, { value: "entitlements", label: "Entitlements" }], get: (r) => r.kind },
        ]}
        empty={<EmptyState title="No uploads yet" icon={<FileUp size={18} />}>Uploads, accepted or rejected, are kept here.</EmptyState>}
      />
      {sel && <UploadPanel id={sel} onClose={() => setSel(null)} />}
    </section>
  );
}

function UploadPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error } = useApi<FlatUploadDetail>(`/flatfile/uploads/${encodeURIComponent(id)}`);
  const changes = useMemo(() => data?.changes ?? [], [data]);
  return (
    <SidePanel title={data ? data.filename : "Upload"} sub={data && <span className="small muted">{KIND_LABEL[data.kind]} · {data.system} · {fmtDate(data.uploaded_at)}</span>} onClose={onClose}>
      {!data ? <Loading error={error} kind="block" /> : (
        <div className="stack-sm">
          <UploadSummary u={data} />
          <p className="small muted">{data.rows_total} rows, {data.size_bytes} bytes, sent by {data.uploaded_by} through the {data.source === "api" ? "API" : "SFTP drop"}. <span className="sys xs">sha256 {data.sha256.slice(0, 16)}…</span></p>
          {data.tasks_confirmed > 0 && <Callout tone="ok">Confirmed {data.tasks_confirmed} manual task(s).</Callout>}
          <RowErrors u={data} />
          {changes.length > 0 && (
            <>
              <h3 className="h-sm">What changed</h3>
              <ul className="plain-list small">
                {changes.map((c: FlatChange, i) => (
                  <li key={i} className="row tight">
                    <Badge tone={c.change === "added" ? "ok" : c.change === "removed" ? "critical" : "info"}>{c.change}</Badge>
                    <span>{KIND_LABEL[c.kind]} · <span className="sys">{c.label}</span>{c.detail && <span className="muted"> ({c.detail})</span>}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </SidePanel>
  );
}

// ---------------------------------------------------------------- manual tasks

function Tasks({ canClose }: { canClose: boolean }) {
  const { data, error, reload } = useApi<{ tasks: FlatTask[] }>("/flatfile/tasks");
  const [closing, setClosing] = useState<FlatTask | null>(null);
  const cols: Column<FlatTask>[] = [
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Badge tone={TASK_TONE[r.status]}>{r.status === "open" ? "Open" : r.status === "confirmed" ? "Confirmed" : "Closed by hand"}</Badge> },
    { id: "task", header: "To do", sort: (r) => r.kind, csv: (r) => r.instruction, cell: (r) => <span className="small"><b>{TASK_LABEL[r.kind]}</b>{r.entitlement && <> <span className="sys">{r.entitlement}</span></>}<br /><span className="muted">{r.instruction}</span></span> },
    { id: "account", header: "Account", sort: (r) => r.account_label, cell: (r) => <span className="small sys">{r.system} · {r.account_label}</span> },
    { id: "why", header: "Because", sort: (r) => r.trigger, cell: (r) => <span className="small">{r.trigger}</span>, hideNarrow: true },
    { id: "at", header: "Opened", sort: (r) => r.created_at, cell: (r) => <span className="small nowrap">{fmtDate(r.created_at)}</span>, hideNarrow: true },
    {
      id: "act", header: "", csv: (r) => (r.status === "closed" ? r.close_reason : ""),
      cell: (r) => r.status === "open" ? (canClose ? <Button size="sm" onClick={() => setClosing(r)}>Close…</Button> : null) : <span className="xs faint">{r.status === "confirmed" ? "By a later upload" : r.close_reason}</span>,
    },
  ];
  return (
    <section aria-label="Manual tasks">
      <h2 className="mt-sm" style={{ marginBottom: 8 }}>Manual tasks</h2>
      <p className="small muted" style={{ marginTop: 0 }}>
        Tessera cannot disable accounts or remove access in these apps. A leaver, revoke or review decision opens a task here, and it stays open until an upload shows the account or entitlement gone.
      </p>
      <DataTable
        id="flatfile-tasks"
        rows={data?.tasks ?? null}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        initialSort={["at", -1]}
        onRefresh={reload}
        initialFilters={{ status: "open" }}
        searchText={(r) => `${r.system} ${r.account_label} ${r.account} ${r.entitlement} ${r.kind} ${r.trigger} ${r.status}`}
        searchPlaceholder="Search account, app or entitlement…"
        filters={[
          { id: "status", label: "Status", options: [{ value: "open", label: "Open" }, { value: "confirmed", label: "Confirmed" }, { value: "closed", label: "Closed by hand" }], get: (r) => r.status },
          { id: "system", label: "App", options: [...new Set((data?.tasks ?? []).map((t) => t.system))].sort().map((s) => ({ value: s, label: s })), get: (r) => r.system },
        ]}
        empty={<EmptyState title="No manual tasks" icon={<ListChecks size={18} />}>Nothing is waiting for someone to do it by hand.</EmptyState>}
      />
      {closing && <CloseDialog task={closing} onClose={() => setClosing(null)} onDone={reload} />}
    </section>
  );
}

function CloseDialog({ task, onClose, onDone }: { task: FlatTask; onClose: () => void; onDone: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useModal(ref, onClose);
  const ready = reason.trim().length >= 10 && !busy;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      await closeFlatTask(task.id, reason.trim());
      toast("Task closed");
      onDone();
      onClose();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <form onSubmit={submit}>
          <div className="dlg-b">
            <h2 id={titleId}>Close this task by hand</h2>
            <p className="muted">{task.instruction}</p>
            <p className="small muted">The usual end of a task is the next upload showing the access gone. Close it by hand only when it no longer applies, and say why: the reason and your name are recorded in the audit log.</p>
            <label className="field mt">
              Reason
              <textarea className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} placeholder="For example: removed in the app's console on 9 October, ticket IT-1234" />
              <span className="small muted">At least 10 characters.</span>
            </label>
            {error && <div className="mt"><Callout tone="bad">{error}</Callout></div>}
          </div>
          <div className="dlg-f">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={!ready}>{busy ? "Closing…" : "Close task"}</Button>
          </div>
        </form>
      </div>
    </div>
  );
}
